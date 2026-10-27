/* Nonce search on a GPU through OpenCL. The CPU still does everything else: it
   computes the header's midstate and hands it to the GPU with the target, and each
   work item of the kernel (src/search.cl) hashes one nonce. */

#include "gpu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_OPENCL

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>

#include "search_cl.h" /* the kernel's source as search_cl, an array of lines; see the Makefile */

/* The kernel's job buffer: midstate, the header's 3 words before the nonce, target limbs. */
#define JOB_WORDS (8 + 3 + 8)
#define NOT_FOUND UINT32_MAX

struct gpu_device {
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_mem job, best;
    uint32_t batch;
    char name[256];
};

static bool failed(cl_int status, const char *what, char *err, size_t err_len) {
    if (status == CL_SUCCESS) {
        return false;
    }
    snprintf(err, err_len, "%s failed (OpenCL error %d)", what, (int)status);
    return true;
}

static bool first_gpu(cl_device_id *device, char *err, size_t err_len) {
    cl_platform_id platforms[16];
    cl_uint count = 0;
    if (clGetPlatformIDs(16, platforms, &count) != CL_SUCCESS || count == 0) {
        snprintf(err, err_len, "no OpenCL driver found (clinfo -l lists what is installed)");
        return false;
    }
    for (cl_uint i = 0; i < count && i < 16; i++) {
        cl_uint n = 0;
        if (clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 1, device, &n) == CL_SUCCESS && n > 0) {
            return true;
        }
    }
    snprintf(err, err_len,
             "no OpenCL GPU found (clinfo -l lists what is installed). Mesa's rusticl driver only "
             "shows AMD GPUs with RUSTICL_ENABLE=radeonsi set, and Intel ones with RUSTICL_ENABLE=iris");
    return false;
}

static bool build_kernel(gpu_device *gpu, cl_device_id device, char *err, size_t err_len) {
    cl_int status;
    cl_uint lines = sizeof(search_cl) / sizeof(search_cl[0]);
    gpu->program = clCreateProgramWithSource(gpu->context, lines, (const char **)search_cl, NULL, &status);
    if (failed(status, "clCreateProgramWithSource", err, err_len)) {
        return false;
    }
    status = clBuildProgram(gpu->program, 1, &device, "", NULL, NULL);
    if (status != CL_SUCCESS) {
        size_t log_len = 0;
        clGetProgramBuildInfo(gpu->program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_len);
        char *log = calloc(1, log_len + 1);
        if (log) {
            clGetProgramBuildInfo(gpu->program, device, CL_PROGRAM_BUILD_LOG, log_len, log, NULL);
        }
        snprintf(err, err_len, "compiling the GPU kernel failed (OpenCL error %d):\n%s", (int)status,
                 log ? log : "");
        free(log);
        return false;
    }
    gpu->kernel = clCreateKernel(gpu->program, "search_nonces", &status);
    return !failed(status, "clCreateKernel", err, err_len);
}

gpu_device *gpu_open(char *err, size_t err_len) {
    gpu_device *gpu = calloc(1, sizeof(*gpu));
    if (!gpu) {
        perror("calloc");
        abort();
    }
    gpu->batch = GPU_BATCH;
    cl_device_id device;
    cl_int status;
    if (!first_gpu(&device, err, err_len)) {
        goto fail;
    }
    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(gpu->name) - 1, gpu->name, NULL);

    gpu->context = clCreateContext(NULL, 1, &device, NULL, NULL, &status);
    if (failed(status, "clCreateContext", err, err_len)) {
        goto fail;
    }
    gpu->queue = clCreateCommandQueue(gpu->context, device, 0, &status);
    if (failed(status, "clCreateCommandQueue", err, err_len) || !build_kernel(gpu, device, err, err_len)) {
        goto fail;
    }
    gpu->job = clCreateBuffer(gpu->context, CL_MEM_READ_ONLY, JOB_WORDS * sizeof(cl_uint), NULL, &status);
    if (failed(status, "clCreateBuffer", err, err_len)) {
        goto fail;
    }
    gpu->best = clCreateBuffer(gpu->context, CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &status);
    if (failed(status, "clCreateBuffer", err, err_len) ||
        failed(clSetKernelArg(gpu->kernel, 0, sizeof(cl_mem), &gpu->job), "clSetKernelArg", err, err_len) ||
        failed(clSetKernelArg(gpu->kernel, 3, sizeof(cl_mem), &gpu->best), "clSetKernelArg", err, err_len)) {
        goto fail;
    }
    return gpu;

fail:
    gpu_close(gpu);
    return NULL;
}

const char *gpu_name(const gpu_device *gpu) {
    return gpu->name;
}

void gpu_close(gpu_device *gpu) {
    if (!gpu) {
        return;
    }
    if (gpu->best) {
        clReleaseMemObject(gpu->best);
    }
    if (gpu->job) {
        clReleaseMemObject(gpu->job);
    }
    if (gpu->kernel) {
        clReleaseKernel(gpu->kernel);
    }
    if (gpu->program) {
        clReleaseProgram(gpu->program);
    }
    if (gpu->queue) {
        clReleaseCommandQueue(gpu->queue);
    }
    if (gpu->context) {
        clReleaseContext(gpu->context);
    }
    free(gpu);
}

void gpu_set_batch(gpu_device *gpu, uint32_t nonces) {
    gpu->batch = nonces;
}

bool gpu_search(gpu_device *gpu, const block_header *header, const uint8_t target[32], uint64_t start,
                uint64_t stop, search_result *result, char *err, size_t err_len) {
    uint32_t job[JOB_WORDS];
    header_midstate(header, job, job + 8);
    for (int i = 0; i < 8; i++) {
        const uint8_t *t = target + 4 * i;
        job[11 + i] = (uint32_t)t[0] | (uint32_t)t[1] << 8 | (uint32_t)t[2] << 16 | (uint32_t)t[3] << 24;
    }
    if (failed(clEnqueueWriteBuffer(gpu->queue, gpu->job, CL_TRUE, 0, sizeof(job), job, 0, NULL, NULL),
               "clEnqueueWriteBuffer", err, err_len)) {
        return false;
    }

    *result = (search_result){0};
    static const cl_uint not_found = NOT_FOUND;
    for (uint64_t base = start; base < stop;) {
        cl_uint count = (cl_uint)(stop - base < gpu->batch ? stop - base : gpu->batch);
        cl_uint base32 = (cl_uint)base, best;
        /* Launch whole work groups of 256; the kernel skips the items past `count`. */
        size_t global_size = ((size_t)count + 255) / 256 * 256;
        if (failed(clEnqueueWriteBuffer(gpu->queue, gpu->best, CL_FALSE, 0, sizeof(not_found), &not_found, 0,
                                        NULL, NULL),
                   "clEnqueueWriteBuffer", err, err_len) ||
            failed(clSetKernelArg(gpu->kernel, 1, sizeof(base32), &base32), "clSetKernelArg", err, err_len) ||
            failed(clSetKernelArg(gpu->kernel, 2, sizeof(count), &count), "clSetKernelArg", err, err_len) ||
            failed(clEnqueueNDRangeKernel(gpu->queue, gpu->kernel, 1, NULL, &global_size, NULL, 0, NULL, NULL),
                   "clEnqueueNDRangeKernel", err, err_len) ||
            failed(clEnqueueReadBuffer(gpu->queue, gpu->best, CL_TRUE, 0, sizeof(best), &best, 0, NULL, NULL),
                   "clEnqueueReadBuffer", err, err_len)) {
            return false;
        }
        result->hashes += count;

        if (best != NOT_FOUND) {
            /* Recheck the GPU's answer, so a kernel or driver bug shows up here rather
               than as a block the node rejects. */
            block_header solved = *header;
            solved.nonce = base32 + best;
            uint8_t hash[32];
            header_hash(&solved, hash);
            if (best >= count || !hash_meets_target(hash, target)) {
                snprintf(err, err_len, "the GPU reported nonce %u, which does not meet the target", solved.nonce);
                return false;
            }
            result->found = true;
            result->nonce = solved.nonce;
            return true;
        }
        base += count;
    }
    return true;
}

#else /* built without OpenCL: gpu_open always fails, so nothing else is reachable */

gpu_device *gpu_open(char *err, size_t err_len) {
    snprintf(err, err_len, "this miner was built without GPU support; rebuild it with: make -C c GPU=1");
    return NULL;
}

const char *gpu_name(const gpu_device *gpu) {
    (void)gpu;
    return "";
}

void gpu_close(gpu_device *gpu) {
    (void)gpu;
}

void gpu_set_batch(gpu_device *gpu, uint32_t nonces) {
    (void)gpu;
    (void)nonces;
}

bool gpu_search(gpu_device *gpu, const block_header *header, const uint8_t target[32], uint64_t start,
                uint64_t stop, search_result *result, char *err, size_t err_len) {
    (void)gpu, (void)header, (void)target, (void)start, (void)stop, (void)result;
    snprintf(err, err_len, "this miner was built without GPU support");
    return false;
}

#endif
