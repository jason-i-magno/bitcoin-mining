#include "block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "tx.h"

static void store_le32(uint8_t *p, uint32_t v) {
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

void header_serialize(const block_header *header, uint8_t out[HEADER_SIZE]) {
    store_le32(out, (uint32_t)header->version);
    memcpy(out + 4, header->prev_block, 32);
    memcpy(out + 36, header->merkle_root, 32);
    store_le32(out + 68, header->timestamp);
    store_le32(out + 72, header->bits);
    store_le32(out + 76, header->nonce);
}

void header_hash(const block_header *header, uint8_t hash[32]) {
    uint8_t raw[HEADER_SIZE];
    header_serialize(header, raw);
    sha256d(raw, sizeof(raw), hash);
}

void header_midstate(const block_header *header, uint32_t midstate[8], uint32_t tail[3]) {
    uint8_t raw[HEADER_SIZE];
    header_serialize(header, raw);
    uint32_t words[16];
    for (int i = 0; i < 16; i++) {
        words[i] = load_be32(raw + 4 * i);
    }
    memcpy(midstate, SHA256_IV, 8 * sizeof(uint32_t));
    sha256_compress(midstate, words);
    for (int i = 0; i < 3; i++) {
        tail[i] = load_be32(raw + 64 + 4 * i);
    }
}

void merkle_root(const uint8_t (*hashes)[32], size_t count, uint8_t root[32]) {
    /* One spare slot for duplicating the last hash of an odd level. */
    uint8_t(*level)[32] = malloc((count + 1) * 32);
    if (!level) {
        perror("malloc");
        abort();
    }
    memcpy(level, hashes, count * 32);
    while (count > 1) {
        if (count % 2) {
            memcpy(level[count], level[count - 1], 32);
            count++;
        }
        for (size_t i = 0; i < count / 2; i++) {
            uint8_t pair[64];
            memcpy(pair, level[2 * i], 32);
            memcpy(pair + 32, level[2 * i + 1], 32);
            sha256d(pair, sizeof(pair), level[i]);
        }
        count /= 2;
    }
    memcpy(root, level[0], 32);
    free(level);
}

void witness_commitment(const uint8_t (*wtxids)[32], size_t count, uint8_t commitment[32]) {
    uint8_t(*leaves)[32] = malloc((count + 1) * 32);
    if (!leaves) {
        perror("malloc");
        abort();
    }
    memset(leaves[0], 0, 32);
    if (count) {
        memcpy(leaves + 1, wtxids, count * 32);
    }

    uint8_t data[64];
    merkle_root((const uint8_t(*)[32])leaves, count + 1, data);
    memcpy(data + 32, WITNESS_RESERVED_VALUE, 32);
    sha256d(data, sizeof(data), commitment);
    free(leaves);
}
