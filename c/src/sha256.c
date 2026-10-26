/* SHA-256 (FIPS 180-4), written out so the mining loop can use its internals. */

#include "sha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const uint32_t SHA256_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

void sha256_compress(uint32_t state[8], const uint32_t block[16]) {
    uint32_t w[64];
    memcpy(w, block, 16 * sizeof(uint32_t));
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void compress_bytes(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(block + 4 * i);
    }
    sha256_compress(state, w);
}

void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->state, SHA256_IV, sizeof(ctx->state));
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = data;
    ctx->total_len += len;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            compress_bytes(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    /* Pad with 0x80, zeros up to 56 mod 64, then the message length in bits. */
    uint64_t bit_len = ctx->total_len * 8;
    static const uint8_t padding[64] = {0x80};
    size_t pad_len = ctx->buffer_len < 56 ? 56 - ctx->buffer_len : 120 - ctx->buffer_len;
    sha256_update(ctx, padding, pad_len);

    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) {
        len_be[i] = bit_len >> (56 - 8 * i);
    }
    sha256_update(ctx, len_be, 8);

    for (int i = 0; i < 8; i++) {
        store_be32(digest + 4 * i, ctx->state[i]);
    }
}

void sha256(const void *data, size_t len, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

void sha256d(const void *data, size_t len, uint8_t digest[32]) {
    uint8_t first[32];
    sha256(data, len, first);
    sha256(first, sizeof(first), digest);
}
