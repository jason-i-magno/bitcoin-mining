#include "tx.h"

#include <string.h>

#include "sha256.h"

const uint8_t WITNESS_RESERVED_VALUE[32] = {0};

static const uint8_t WITNESS_COMMITMENT_HEADER[4] = {0xaa, 0x21, 0xa9, 0xed};
#define OP_RETURN 0x6a

void witness_commitment_script(const uint8_t commitment[32], uint8_t script[WITNESS_COMMITMENT_SCRIPT_SIZE]) {
    script[0] = OP_RETURN;
    script[1] = 36; /* push the next 36 bytes */
    memcpy(script + 2, WITNESS_COMMITMENT_HEADER, 4);
    memcpy(script + 6, commitment, 32);
}

bool coinbase_build(coinbase_tx *cb, uint32_t height, const uint8_t *extranonce, size_t extranonce_len,
                    uint64_t value, const uint8_t *script_pubkey, size_t script_pubkey_len,
                    const uint8_t *witness_commitment, const char *tag) {
    buf_t script_sig = {0};
    buf_push_int(&script_sig, height);
    buf_push_data(&script_sig, extranonce, extranonce_len);
    buf_push_data(&script_sig, (const uint8_t *)tag, strlen(tag));
    bool ok = script_sig.len >= 2 && script_sig.len <= MAX_SCRIPT_SIG && script_pubkey_len <= MAX_SCRIPT_PUBKEY;
    if (ok) {
        *cb = (coinbase_tx){.version = 2, .script_sig_len = script_sig.len, .value = value,
                            .script_pubkey_len = script_pubkey_len};
        memcpy(cb->script_sig, script_sig.data, script_sig.len);
        memcpy(cb->script_pubkey, script_pubkey, script_pubkey_len);
        if (witness_commitment) {
            cb->has_witness_commitment = true;
            memcpy(cb->witness_commitment, witness_commitment, 32);
        }
    }
    buf_free(&script_sig);
    return ok;
}

void coinbase_serialize(const coinbase_tx *cb, bool include_witness, buf_t *out) {
    bool witness = include_witness && cb->has_witness_commitment;
    buf_le32(out, cb->version);
    if (witness) {
        buf_u8(out, 0x00); /* segwit marker */
        buf_u8(out, 0x01); /* and flag */
    }

    buf_compact_size(out, 1); /* one input, spending the null prevout */
    static const uint8_t null_txid[32] = {0};
    buf_append(out, null_txid, 32);
    buf_le32(out, 0xFFFFFFFF);
    buf_compact_size(out, cb->script_sig_len);
    buf_append(out, cb->script_sig, cb->script_sig_len);
    buf_le32(out, 0xFFFFFFFF); /* sequence */

    buf_compact_size(out, cb->has_witness_commitment ? 2 : 1);
    buf_le64(out, cb->value);
    buf_compact_size(out, cb->script_pubkey_len);
    buf_append(out, cb->script_pubkey, cb->script_pubkey_len);
    if (cb->has_witness_commitment) {
        uint8_t script[WITNESS_COMMITMENT_SCRIPT_SIZE];
        witness_commitment_script(cb->witness_commitment, script);
        buf_le64(out, 0);
        buf_compact_size(out, sizeof(script));
        buf_append(out, script, sizeof(script));
    }

    if (witness) {
        buf_compact_size(out, 1); /* one witness item... */
        buf_compact_size(out, 32);
        buf_append(out, WITNESS_RESERVED_VALUE, 32); /* ...the reserved value */
    }
    buf_le32(out, 0); /* locktime */
}

void coinbase_txid(const coinbase_tx *cb, uint8_t txid[32]) {
    buf_t raw = {0};
    coinbase_serialize(cb, false, &raw);
    sha256d(raw.data, raw.len, txid);
    buf_free(&raw);
}
