/* Turn a block template into a candidate block, then search for a nonce that solves it. */

#include "mining.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sha256.h"

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static bool template_string(const json *t, const char *key, const char **out, char *err, size_t err_len) {
    *out = json_get_string(t, key);
    if (!*out) {
        snprintf(err, err_len, "template has no string \"%s\"", key);
    }
    return *out != NULL;
}

static bool template_int(const json *t, const char *key, int64_t *out, char *err, size_t err_len) {
    if (!json_get_int(t, key, out)) {
        snprintf(err, err_len, "template has no integer \"%s\"", key);
        return false;
    }
    return true;
}

bool build_candidate(const json *template, const uint8_t *script_pubkey, size_t script_pubkey_len,
                     uint64_t extranonce, candidate *out, char *err, size_t err_len) {
    *out = (candidate){0};
    const json *txs = json_get(template, "transactions");
    const char *prev_hash, *bits_hex, *target_hex;
    int64_t height, version, curtime, coinbase_value;
    if (!txs || txs->type != JSON_ARRAY) {
        snprintf(err, err_len, "template has no \"transactions\" array");
        return false;
    }
    if (!template_string(template, "previousblockhash", &prev_hash, err, err_len) ||
        !template_string(template, "bits", &bits_hex, err, err_len) ||
        !template_string(template, "target", &target_hex, err, err_len) ||
        !template_int(template, "height", &height, err, err_len) ||
        !template_int(template, "version", &version, err, err_len) ||
        !template_int(template, "curtime", &curtime, err, err_len) ||
        !template_int(template, "coinbasevalue", &coinbase_value, err, err_len)) {
        return false;
    }

    /* txids[0] is reserved for the coinbase, which we build below. */
    size_t n = txs->count;
    uint8_t(*txids)[32] = malloc((n + 1) * 32);
    uint8_t(*wtxids)[32] = malloc((n + 1) * 32);
    bool ok = false;
    if (!txids || !wtxids) {
        snprintf(err, err_len, "out of memory");
        goto done;
    }
    for (size_t i = 0; i < n; i++) {
        const json *tx = &txs->items[i];
        const char *data = json_get_string(tx, "data");
        const char *txid = json_get_string(tx, "txid");
        const char *wtxid = json_get_string(tx, "hash");
        if (!data || !txid || !wtxid || !from_display_hex(txid, txids[i + 1]) ||
            !from_display_hex(wtxid, wtxids[i]) || !hex_decode_append(data, &out->transactions)) {
            snprintf(err, err_len, "template transaction %zu is malformed", i);
            goto done;
        }
    }
    out->tx_count = n;

    uint8_t commitment[32];
    const char *node_commitment = json_get_string(template, "default_witness_commitment");
    if (node_commitment) {
        witness_commitment((const uint8_t(*)[32])wtxids, n, commitment);
        /* The node computed the same value; a mismatch means our witness merkle tree is wrong. */
        uint8_t ours[WITNESS_COMMITMENT_SCRIPT_SIZE], theirs[WITNESS_COMMITMENT_SCRIPT_SIZE];
        witness_commitment_script(commitment, ours);
        if (!hex_decode(node_commitment, theirs, sizeof(theirs)) || memcmp(ours, theirs, sizeof(ours)) != 0) {
            snprintf(err, err_len, "computed witness commitment does not match the node's");
            goto done;
        }
    }

    uint8_t extranonce_bytes[EXTRANONCE_SIZE];
    for (int i = 0; i < EXTRANONCE_SIZE; i++) {
        extranonce_bytes[i] = (uint8_t)(extranonce >> (8 * i));
    }
    if (!coinbase_build(&out->coinbase, (uint32_t)height, extranonce_bytes, sizeof(extranonce_bytes),
                        (uint64_t)coinbase_value, script_pubkey, script_pubkey_len,
                        node_commitment ? commitment : NULL, DEFAULT_COINBASE_TAG)) {
        snprintf(err, err_len, "coinbase scriptSig or payout script too long");
        goto done;
    }
    coinbase_txid(&out->coinbase, txids[0]);

    uint8_t bits_be[4];
    if (!from_display_hex(prev_hash, out->header.prev_block) || !hex_decode(bits_hex, bits_be, 4)) {
        snprintf(err, err_len, "template has a malformed previousblockhash or bits");
        goto done;
    }
    out->header.version = (int32_t)version;
    merkle_root((const uint8_t(*)[32])txids, n + 1, out->header.merkle_root);
    out->header.timestamp = (uint32_t)curtime;
    out->header.bits = load_be32(bits_be);
    out->height = (uint32_t)height;

    uint8_t node_target[32];
    bits_to_target(out->header.bits, out->target);
    if (!from_display_hex(target_hex, node_target) || memcmp(node_target, out->target, 32) != 0) {
        snprintf(err, err_len, "decoded nBits does not match the node's target");
        goto done;
    }
    ok = true;

done:
    free(txids);
    free(wtxids);
    if (!ok) {
        candidate_free(out);
    }
    return ok;
}

void candidate_serialize(const candidate *c, buf_t *out) {
    uint8_t header[HEADER_SIZE];
    header_serialize(&c->header, header);
    buf_append(out, header, sizeof(header));
    buf_compact_size(out, 1 + c->tx_count);
    coinbase_serialize(&c->coinbase, true, out);
    buf_append(out, c->transactions.data, c->transactions.len);
}

void candidate_free(candidate *c) {
    buf_free(&c->transactions);
}

typedef struct {
    const uint32_t *midstate;
    const uint32_t *tail;
    const uint8_t *target;
    atomic_bool *stop_flag;
    uint64_t start, stop;
    bool found;
    uint32_t nonce;
    uint64_t hashes;
} search_job;

static void *search_worker(void *arg) {
    search_job *job = arg;
    /* The header's second 64-byte block: its last 16 bytes followed by SHA-256 padding
       for an 80-byte (640-bit) message. Only word 3, the nonce, changes. */
    uint32_t block1[16] = {job->tail[0], job->tail[1], job->tail[2], 0, 0x80000000, [15] = 640};
    /* The second SHA-256 hashes the 32-byte first digest: 8 words, then padding for 256 bits. */
    uint32_t block2[16] = {[8] = 0x80000000, [15] = 256};
    /* The top 32 bits of the target. A hash above them fails without a full comparison. */
    const uint8_t *t = job->target;
    uint32_t target_top = (uint32_t)t[31] << 24 | (uint32_t)t[30] << 16 | (uint32_t)t[29] << 8 | t[28];

    uint64_t nonce = job->start;
    for (; nonce < job->stop; nonce++) {
        if ((nonce & 0xFFFF) == 0 && atomic_load_explicit(job->stop_flag, memory_order_relaxed)) {
            break;
        }
        uint32_t state[8];
        memcpy(state, job->midstate, sizeof(state));
        /* The header stores the nonce little-endian; SHA-256 reads words big-endian. */
        block1[3] = __builtin_bswap32((uint32_t)nonce);
        sha256_compress(state, block1);

        memcpy(block2, state, sizeof(state));
        memcpy(state, SHA256_IV, sizeof(state));
        sha256_compress(state, block2);

        /* Read as a little-endian number, the digest's most significant bytes are its
           last four, i.e. state[7] byte-swapped. */
        if (__builtin_bswap32(state[7]) > target_top) {
            continue;
        }
        uint8_t digest[32];
        for (int i = 0; i < 8; i++) {
            store_be32(digest + 4 * i, state[i]);
        }
        if (hash_meets_target(digest, job->target)) {
            job->found = true;
            job->nonce = (uint32_t)nonce;
            atomic_store(job->stop_flag, true);
            nonce++; /* count this attempt */
            break;
        }
    }
    job->hashes = nonce - job->start;
    return NULL;
}

search_result search(const block_header *header, const uint8_t target[32], uint64_t start, uint64_t stop,
                     int threads) {
    uint8_t raw[HEADER_SIZE];
    header_serialize(header, raw);

    /* SHA-256 consumes 64-byte blocks, and the first 64 header bytes don't depend on
       the nonce. Hash them once and resume from that "midstate" for every attempt. */
    uint32_t midstate[8], words[16];
    memcpy(midstate, SHA256_IV, sizeof(midstate));
    for (int i = 0; i < 16; i++) {
        words[i] = load_be32(raw + 4 * i);
    }
    sha256_compress(midstate, words);
    uint32_t tail[3] = {load_be32(raw + 64), load_be32(raw + 68), load_be32(raw + 72)};

    if (threads < 1) {
        threads = 1;
    }
    if ((uint64_t)threads > stop - start) {
        threads = stop > start ? (int)(stop - start) : 1;
    }
    search_job *jobs = calloc((size_t)threads, sizeof(search_job));
    pthread_t *ids = calloc((size_t)threads, sizeof(pthread_t));
    bool *started = calloc((size_t)threads, sizeof(bool));
    if (!jobs || !ids || !started) {
        perror("calloc");
        abort();
    }

    atomic_bool stop_flag = false;
    uint64_t span = (stop - start) / (uint64_t)threads;
    for (int i = 0; i < threads; i++) {
        jobs[i] = (search_job){
            .midstate = midstate,
            .tail = tail,
            .target = target,
            .stop_flag = &stop_flag,
            .start = start + (uint64_t)i * span,
            .stop = i == threads - 1 ? stop : start + (uint64_t)(i + 1) * span,
        };
    }
    /* Run slice 0 on this thread; if a thread can't be created, run its slice here too. */
    for (int i = 1; i < threads; i++) {
        started[i] = pthread_create(&ids[i], NULL, search_worker, &jobs[i]) == 0;
    }
    search_worker(&jobs[0]);
    for (int i = 1; i < threads; i++) {
        if (started[i]) {
            pthread_join(ids[i], NULL);
        } else {
            search_worker(&jobs[i]);
        }
    }

    search_result result = {0};
    for (int i = 0; i < threads; i++) {
        result.hashes += jobs[i].hashes;
        if (jobs[i].found && (!result.found || jobs[i].nonce < result.nonce)) {
            result.found = true;
            result.nonce = jobs[i].nonce;
        }
    }
    free(jobs);
    free(ids);
    free(started);
    return result;
}

static json *fetch_template(rpc_client *rpc) {
    return rpc_call(rpc, "getblocktemplate", "[{\"rules\":[\"segwit\"]}]");
}

bool mine_block(rpc_client *rpc, const uint8_t *script_pubkey, size_t script_pubkey_len, int threads,
                mined_block *out, char *err, size_t err_len) {
    double started = now(), fetched_at = started;
    json *template = fetch_template(rpc);
    if (!template) {
        snprintf(err, err_len, "%s", rpc->error);
        return false;
    }
    uint64_t extranonce = 0, nonce_start = 0, attempts = 0;
    candidate cand;
    bool ok = false;

    for (;;) {
        if (now() - fetched_at > TEMPLATE_MAX_AGE) {
            /* Pick up a new tip, new mempool transactions, and a current timestamp. */
            printf("  %.2f MH/s, refreshing template\n", (double)attempts / (now() - started) / 1e6);
            fflush(stdout);
            json_free(template);
            template = fetch_template(rpc);
            if (!template) {
                snprintf(err, err_len, "%s", rpc->error);
                return false;
            }
            fetched_at = now();
            nonce_start = 0;
        }

        if (!build_candidate(template, script_pubkey, script_pubkey_len, extranonce, &cand, err, err_len)) {
            break;
        }
        uint64_t stop = nonce_start + CHUNK_SIZE < NONCE_SPACE ? nonce_start + CHUNK_SIZE : NONCE_SPACE;
        search_result r = search(&cand.header, cand.target, nonce_start, stop, threads);
        attempts += r.hashes;

        if (!r.found) {
            candidate_free(&cand);
            nonce_start = stop;
            if (nonce_start == NONCE_SPACE) {
                /* Every nonce failed. A new extranonce changes the coinbase txid, and
                   with it the merkle root, giving another 2^32 headers to try. */
                extranonce++;
                nonce_start = 0;
            }
            continue;
        }

        cand.header.nonce = r.nonce;
        buf_t block = {0}, params = {0};
        candidate_serialize(&cand, &block);
        buf_append_str(&params, "[\"");
        hex_encode_append(block.data, block.len, &params);
        buf_append_str(&params, "\"]");
        buf_u8(&params, '\0');
        json *result = rpc_call(rpc, "submitblock", (const char *)params.data);
        buf_free(&block);
        buf_free(&params);

        if (!result) {
            snprintf(err, err_len, "%s", rpc->error);
        } else if (result->type != JSON_NULL) {
            /* submitblock returns null on success, or a reason string such as "high-hash". */
            snprintf(err, err_len, "node rejected block at height %u: %s", cand.height,
                     result->type == JSON_STRING ? result->string : "(non-string reply)");
        } else {
            uint8_t hash[32];
            header_hash(&cand.header, hash);
            *out = (mined_block){
                .height = cand.height,
                .nonce = r.nonce,
                .extranonce = extranonce,
                .tx_count = 1 + cand.tx_count,
                .attempts = attempts,
                .seconds = now() - started,
            };
            to_display_hex(hash, out->hash);
            ok = true;
        }
        json_free(result);
        candidate_free(&cand);
        break;
    }
    json_free(template);
    return ok;
}
