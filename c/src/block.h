#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>

#define HEADER_SIZE 80

typedef struct {
    int32_t version;
    uint8_t prev_block[32];  /* internal byte order */
    uint8_t merkle_root[32]; /* internal byte order */
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} block_header;

/* The 80 bytes that get hashed. */
void header_serialize(const block_header *header, uint8_t out[HEADER_SIZE]);
void header_hash(const block_header *header, uint8_t hash[32]);

/* Hash pairs level by level until one hash remains. Odd levels duplicate their
   last hash. `count` must be at least 1. */
void merkle_root(const uint8_t (*hashes)[32], size_t count, uint8_t root[32]);

/* BIP141 commitment to every transaction's witness data, given the non-coinbase
   wtxids. The coinbase's wtxid is defined as all zeros, since it can't commit to itself. */
void witness_commitment(const uint8_t (*wtxids)[32], size_t count, uint8_t commitment[32]);

#endif
