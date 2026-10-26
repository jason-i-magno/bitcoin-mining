#include "rpc.h"

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define RPC_TIMEOUT_SECONDS 60

static bool fail(rpc_client *rpc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(rpc->error, sizeof(rpc->error), fmt, args);
    va_end(args);
    return false;
}

static void base64_encode(const uint8_t *in, size_t len, char *out) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = table[v >> 18 & 63];
        out[o++] = table[v >> 12 & 63];
        out[o++] = i + 1 < len ? table[v >> 6 & 63] : '=';
        out[o++] = i + 2 < len ? table[v & 63] : '=';
    }
    out[o] = '\0';
}

static bool copy_field(char *dst, size_t dst_size, const char *src, size_t len) {
    if (len == 0 || len >= dst_size) {
        return false;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

static bool parse_url(rpc_client *rpc, const char *url) {
    const char *scheme = "http://";
    if (strncmp(url, scheme, strlen(scheme)) != 0) {
        return fail(rpc, "only http:// URLs are supported: %s", url);
    }
    const char *host = url + strlen(scheme), *host_end;
    const char *rest;
    if (*host == '[') { /* IPv6 literal, e.g. http://[::1]:18443 */
        host++;
        host_end = strchr(host, ']');
        if (!host_end) {
            return fail(rpc, "bad URL: %s", url);
        }
        rest = host_end + 1;
    } else {
        host_end = host + strcspn(host, ":/");
        rest = host_end;
    }
    if (!copy_field(rpc->host, sizeof(rpc->host), host, (size_t)(host_end - host))) {
        return fail(rpc, "bad host in URL: %s", url);
    }

    const char *path = strchr(rest, '/');
    if (*rest == ':') {
        size_t port_len = path ? (size_t)(path - rest - 1) : strlen(rest + 1);
        if (!copy_field(rpc->port, sizeof(rpc->port), rest + 1, port_len)) {
            return fail(rpc, "bad port in URL: %s", url);
        }
    } else {
        strcpy(rpc->port, "80");
    }
    if (!copy_field(rpc->path, sizeof(rpc->path), path ? path : "/", strlen(path ? path : "/"))) {
        return fail(rpc, "URL path too long: %s", url);
    }
    return true;
}

bool rpc_init(rpc_client *rpc, const char *url, const char *user, const char *password) {
    *rpc = (rpc_client){0};
    if (!parse_url(rpc, url)) {
        return false;
    }
    char credentials[256];
    int n = snprintf(credentials, sizeof(credentials), "%s:%s", user, password);
    if (n < 0 || (size_t)n >= sizeof(credentials)) {
        return fail(rpc, "RPC username/password too long");
    }
    strcpy(rpc->auth, "Basic ");
    base64_encode((const uint8_t *)credentials, (size_t)n, rpc->auth + strlen(rpc->auth));
    return true;
}

bool rpc_init_cookie(rpc_client *rpc, const char *url, const char *cookie_path) {
    *rpc = (rpc_client){0};
    FILE *f = fopen(cookie_path, "r");
    if (!f) {
        return fail(rpc, "cannot read RPC cookie %s: %s", cookie_path, strerror(errno));
    }
    char cookie[256] = {0};
    bool read_ok = fgets(cookie, sizeof(cookie), f) != NULL;
    fclose(f);
    cookie[strcspn(cookie, "\r\n")] = '\0';
    char *colon = strchr(cookie, ':');
    if (!read_ok || !colon) {
        return fail(rpc, "malformed RPC cookie %s", cookie_path);
    }
    *colon = '\0';
    return rpc_init(rpc, url, cookie, colon + 1);
}

static int connect_to(rpc_client *rpc) {
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *addrs;
    int rc = getaddrinfo(rpc->host, rpc->port, &hints, &addrs);
    if (rc != 0) {
        fail(rpc, "cannot resolve %s: %s", rpc->host, gai_strerror(rc));
        return -1;
    }
    int fd = -1, last_errno = 0;
    for (struct addrinfo *ai = addrs; ai && fd < 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            last_errno = errno;
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(addrs);
    if (fd < 0) {
        fail(rpc, "cannot connect to %s:%s: %s", rpc->host, rpc->port, strerror(last_errno));
        return -1;
    }
    struct timeval timeout = {.tv_sec = RPC_TIMEOUT_SECONDS};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

static bool write_all(int fd, const void *data, size_t len) {
    const uint8_t *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

/* POST `body` and read the whole response; we send "Connection: close", so the
   server closes the socket when it is done. Returns the HTTP status, or -1. */
static int http_post(rpc_client *rpc, const buf_t *body, buf_t *response) {
    int fd = connect_to(rpc);
    if (fd < 0) {
        return -1;
    }
    char headers[1024];
    int n = snprintf(headers, sizeof(headers),
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Authorization: %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     rpc->path, rpc->host, rpc->auth, body->len);
    if (n < 0 || (size_t)n >= sizeof(headers) || !write_all(fd, headers, (size_t)n) ||
        !write_all(fd, body->data, body->len)) {
        close(fd);
        fail(rpc, "failed to send request: %s", strerror(errno));
        return -1;
    }

    char chunk[65536];
    ssize_t got;
    while ((got = read(fd, chunk, sizeof(chunk))) != 0) {
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got < 0) {
            close(fd);
            fail(rpc, "failed to read response: %s", strerror(errno));
            return -1;
        }
        buf_append(response, chunk, (size_t)got);
    }
    close(fd);
    buf_u8(response, '\0'); /* so the headers can be searched as a C string */
    response->len--;

    int status;
    if (sscanf((const char *)response->data, "HTTP/1.%*d %d", &status) != 1) {
        fail(rpc, "malformed HTTP response");
        return -1;
    }
    return status;
}

/* Does the header block declare "Transfer-Encoding: chunked"? Header names are case-insensitive. */
static bool is_chunked(const char *headers, size_t len) {
    char *lower = malloc(len + 1);
    if (!lower) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)(headers[i] >= 'A' && headers[i] <= 'Z' ? headers[i] + 32 : headers[i]);
    }
    lower[len] = '\0';
    const char *field = strstr(lower, "\r\ntransfer-encoding:");
    bool chunked = false;
    if (field) {
        const char *line_end = strstr(field + 2, "\r\n");
        const char *value = strstr(field, "chunked");
        chunked = value && (!line_end || value < line_end);
    }
    free(lower);
    return chunked;
}

bool http_dechunk(const char *body, size_t len, buf_t *out) {
    const char *p = body, *end = body + len;
    for (;;) {
        /* Each chunk is "<hex size>[;extensions]\r\n<data>\r\n"; a zero size ends the body. */
        size_t size = 0;
        int digits = 0;
        for (; p < end; p++, digits++) {
            char c = *p;
            int v = c >= '0' && c <= '9' ? c - '0'
                  : c >= 'a' && c <= 'f' ? c - 'a' + 10
                  : c >= 'A' && c <= 'F' ? c - 'A' + 10
                  : -1;
            if (v < 0) {
                break;
            }
            if (size > (SIZE_MAX >> 4)) {
                return false;
            }
            size = size << 4 | (size_t)v;
        }
        const char *line_end = p;
        while (line_end + 1 < end && !(line_end[0] == '\r' && line_end[1] == '\n')) {
            line_end++;
        }
        if (digits == 0 || line_end + 1 >= end) {
            return false;
        }
        p = line_end + 2;
        if (size == 0) {
            return true;
        }
        if ((size_t)(end - p) < size + 2) {
            return false;
        }
        buf_append(out, p, size);
        p += size + 2;
    }
}

json *rpc_call(rpc_client *rpc, const char *method, const char *params) {
    buf_t request = {0};
    buf_append_str(&request, "{\"jsonrpc\":\"1.0\",\"id\":\"miner\",\"method\":");
    json_write_string(&request, method);
    buf_append_str(&request, ",\"params\":");
    buf_append_str(&request, params);
    buf_u8(&request, '}');

    buf_t response = {0};
    int status = http_post(rpc, &request, &response);
    buf_free(&request);
    if (status < 0) {
        buf_free(&response);
        return NULL;
    }
    if (status == 401) {
        buf_free(&response);
        fail(rpc, "HTTP 401 Unauthorized: check the RPC cookie or --rpc-user/--rpc-password");
        return NULL;
    }

    const char *text = (const char *)response.data;
    const char *body = strstr(text, "\r\n\r\n");
    if (!body) {
        buf_free(&response);
        fail(rpc, "malformed HTTP response (HTTP %d)", status);
        return NULL;
    }
    body += 4;
    size_t body_len = response.len - (size_t)(body - text);

    /* bitcoind reports RPC errors as HTTP 4xx/5xx with a JSON body, so parse whatever came back. */
    json *reply;
    if (is_chunked(text, (size_t)(body - text))) {
        buf_t decoded = {0};
        reply = http_dechunk(body, body_len, &decoded) ? json_parse((const char *)decoded.data, decoded.len) : NULL;
        buf_free(&decoded);
    } else {
        reply = json_parse(body, body_len);
    }
    buf_free(&response);
    if (!reply) {
        fail(rpc, "unparseable reply to %s (HTTP %d)", method, status);
        return NULL;
    }

    const json *error = json_get(reply, "error");
    if (error && error->type != JSON_NULL) {
        const char *message = json_get_string(error, "message");
        int64_t code = 0;
        json_get_int(error, "code", &code);
        fail(rpc, "%s: %s (code %lld)", method, message ? message : "unknown error", (long long)code);
        json_free(reply);
        return NULL;
    }

    /* Move "result" out of the reply so only it survives. */
    json *result = calloc(1, sizeof(json));
    json *slot = (json *)json_get(reply, "result");
    if (!result) {
        fail(rpc, "out of memory");
    } else if (slot) {
        char *key = slot->key;
        *result = *slot;
        result->key = NULL;
        *slot = (json){.key = key};
    }
    json_free(reply);
    return result;
}
