#ifndef GPU_H
#define GPU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"
#include "mining.h"

/* Nonces per kernel launch: around 20 ms of work, so a GPU that also drives a display
   stays usable, and a found block is noticed quickly. */
#define GPU_BATCH (UINT32_C(1) << 24)

/* An OpenCL GPU with the search kernel compiled and ready. */
typedef struct gpu_device gpu_device;

/* Open the first GPU that OpenCL reports. Fails with a message in `err`, including
   when the miner was built without OpenCL (make GPU=1 adds it). */
gpu_device *gpu_open(char *err, size_t err_len);
const char *gpu_name(const gpu_device *gpu);
void gpu_close(gpu_device *gpu);

/* Try nonces in [start, stop) on the GPU, one launch of `GPU_BATCH` nonces at a time.
   Like a one-thread CPU search, the result is the first valid nonce in the range, and
   it is rechecked on the CPU. `hashes` counts every nonce in the launches made. Fails
   with a message in `err` on an OpenCL error, or if the GPU reports a wrong answer. */
bool gpu_search(gpu_device *gpu, const block_header *header, const uint8_t target[32], uint64_t start,
                uint64_t stop, search_result *result, char *err, size_t err_len);

/* Change the launch size. Tests use small ones to cover results in later launches. */
void gpu_set_batch(gpu_device *gpu, uint32_t nonces);

#endif
