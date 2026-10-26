#ifndef SHA256_H
#define SHA256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint8_t buffer[64];
    size_t buffer_len;
    uint64_t total_len;
} sha256_ctx;

extern const uint32_t SHA256_IV[8];
extern const uint32_t SHA256_K[64];

/* A compression function: it processes one 64-byte block, given as 16 big-endian
   words already loaded into native integers. */
typedef void sha256_compress_fn(uint32_t state[8], const uint32_t block[16]);

/* Run the fastest compression function this CPU supports. Exposed so the miner can
   resume from a midstate and skip byte conversions. */
void sha256_compress(uint32_t state[8], const uint32_t block[16]);

/* The implementations sha256_compress picks from. */
void sha256_compress_generic(uint32_t state[8], const uint32_t block[16]);
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define SHA256_HAVE_SHANI 1
/* The x86 SHA extensions. Call it only if sha256_shani_supported() returns true. */
void sha256_compress_shani(uint32_t state[8], const uint32_t block[16]);
bool sha256_shani_supported(void);
#endif

/* Make sha256_compress use `fn`, or pass NULL to go back to the fastest one. Call it
   before starting threads that hash. Tests use it to cover each implementation. */
void sha256_use(sha256_compress_fn *fn);

/* The implementation sha256_compress is using: "SHA-NI" or "generic". */
const char *sha256_implementation(void);

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
