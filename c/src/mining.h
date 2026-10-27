#ifndef MINING_H
#define MINING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "block.h"
#include "encoding.h"
#include "json.h"
#include "rpc.h"
#include "tx.h"

#define NONCE_SPACE (UINT64_C(1) << 32)
#define EXTRANONCE_SIZE 8
#define CHUNK_SIZE (UINT64_C(1) << 26) /* nonces to try between checks for a fresher template */
#define TEMPLATE_MAX_AGE 30            /* seconds before asking the node for a new template */

typedef struct gpu_device gpu_device; /* gpu.h */

/* A complete block, except that its header nonce may not satisfy the target yet. */
typedef struct {
    block_header header;
    coinbase_tx coinbase;
    buf_t transactions; /* the template's other transactions, serialized back to back */
    size_t tx_count;    /* not counting the coinbase */
    uint8_t target[32]; /* little-endian */
    uint32_t height;
} candidate;

typedef struct {
    bool found;
    uint32_t nonce;
    uint64_t hashes; /* attempts made across all threads */
} search_result;

typedef struct {
    uint32_t height;
    char hash[65];
    uint32_t nonce;
    uint64_t extranonce;
    size_t tx_count;
    uint64_t attempts;
    double seconds;
} mined_block;

/* Build a candidate from a getblocktemplate reply. Fails with a message in `err` if
   the template is malformed, or if our witness commitment or decoded target disagree
   with the node's. Free the result with candidate_free. */
bool build_candidate(const json *template, const uint8_t *script_pubkey, size_t script_pubkey_len,
                     uint64_t extranonce, candidate *out, char *err, size_t err_len);
void candidate_serialize(const candidate *c, buf_t *out);
void candidate_free(candidate *c);

/* Try nonces in [start, stop) split across `threads` threads, stopping everyone at
   the first hit. With one thread the result is the first valid nonce in the range. */
search_result search(const block_header *header, const uint8_t target[32], uint64_t start, uint64_t stop,
                     int threads);

/* Mine and submit one block on top of the node's current tip, hashing on `gpu` if it
   isn't NULL, otherwise on `threads` CPU threads. */
bool mine_block(rpc_client *rpc, const uint8_t *script_pubkey, size_t script_pubkey_len, int threads,
                gpu_device *gpu, mined_block *out, char *err, size_t err_len);

#endif
