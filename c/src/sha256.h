#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    size_t buffer_len;
    uint64_t total_len;
} sha256_ctx;

extern const uint32_t SHA256_IV[8];

/* Run the compression function on one 64-byte block, given as 16 big-endian words.
   Exposed so the miner can resume from a midstate and skip byte conversions. */
void sha256_compress(uint32_t state[8], const uint32_t block[16]);

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[32]);

void sha256(const void *data, size_t len, uint8_t digest[32]);

/* Bitcoin's hash function: SHA-256 applied twice. */
void sha256d(const void *data, size_t len, uint8_t digest[32]);

static inline uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

#endif
