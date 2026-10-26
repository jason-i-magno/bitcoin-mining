#ifndef TX_H
#define TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "encoding.h"

#define MAX_SCRIPT_SIG 100 /* consensus limit for a coinbase scriptSig */
#define MAX_SCRIPT_PUBKEY 128
#define WITNESS_COMMITMENT_SCRIPT_SIZE 38

/* BIP141: the coinbase's single witness item. */
extern const uint8_t WITNESS_RESERVED_VALUE[32];

#define DEFAULT_COINBASE_TAG "/c-regtest-miner/"

/* The transaction that pays the block reward. It has one input, which spends
   nothing, and one payout output, plus a witness commitment output for segwit blocks. */
typedef struct {
    uint32_t version;
    uint8_t script_sig[MAX_SCRIPT_SIG];
    size_t script_sig_len;
    uint64_t value; /* satoshis */
    uint8_t script_pubkey[MAX_SCRIPT_PUBKEY];
    size_t script_pubkey_len;
    bool has_witness_commitment;
    uint8_t witness_commitment[32];
} coinbase_tx;

/* The scriptSig carries the height (required by BIP34), then the extranonce,
   which the miner changes to get a new merkle root once the header nonce is exhausted.
   Fails if the scriptSig would exceed 100 bytes or the script_pubkey is too long. */
bool coinbase_build(coinbase_tx *cb, uint32_t height, const uint8_t *extranonce, size_t extranonce_len,
                    uint64_t value, const uint8_t *script_pubkey, size_t script_pubkey_len,
                    const uint8_t *witness_commitment, const char *tag);

void coinbase_serialize(const coinbase_tx *cb, bool include_witness, buf_t *out);

/* Hash of the serialization *without* witness data, in internal byte order.
   This is what goes into the block's merkle root. */
void coinbase_txid(const coinbase_tx *cb, uint8_t txid[32]);

void witness_commitment_script(const uint8_t commitment[32], uint8_t script[WITNESS_COMMITMENT_SCRIPT_SIZE]);

#endif
