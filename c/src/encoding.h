#ifndef ENCODING_H
#define ENCODING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A growable byte buffer. Zero-initialize it ({0}) before use. */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buf_t;

void buf_append(buf_t *b, const void *data, size_t len);
void buf_append_str(buf_t *b, const char *s);
void buf_u8(buf_t *b, uint8_t v);
void buf_le32(buf_t *b, uint32_t v);
void buf_le64(buf_t *b, uint64_t v);
void buf_free(buf_t *b);

/* Variable-length integer used for counts and lengths in transactions and blocks. */
void buf_compact_size(buf_t *b, uint64_t n);

/* Script that pushes `data` onto the stack, using the smallest push opcode. */
void buf_push_data(buf_t *b, const uint8_t *data, size_t len);

/* Script that pushes a non-negative integer, byte-for-byte like Bitcoin Core's
   `CScript() << n`. BIP34 requires the coinbase scriptSig to start with exactly this
   encoding of the block height, so heights 1-16 must use OP_1..OP_16. */
void buf_push_int(buf_t *b, uint64_t n);

/* Decode exactly `out_len` bytes; fails on bad characters or the wrong length. */
bool hex_decode(const char *hex, uint8_t *out, size_t out_len);
/* Decode any even-length hex string, appending to `out`. */
bool hex_decode_append(const char *hex, buf_t *out);
/* Writes 2 * len characters plus a terminating NUL. */
void hex_encode(const uint8_t *data, size_t len, char *out);
void hex_encode_append(const uint8_t *data, size_t len, buf_t *out);

/* Hashes are displayed byte-reversed, so the hex shown by RPC and explorers is
   backwards relative to the bytes that get hashed and serialized. */
bool from_display_hex(const char *hex, uint8_t out[32]);
void to_display_hex(const uint8_t hash[32], char out[65]);

/* Decode the header's compact "nBits" field into a 256-bit target, stored
   little-endian. The top byte is a base-256 exponent and the low 3 bytes a mantissa:
   target = mantissa * 256^(exponent - 3). */
void bits_to_target(uint32_t bits, uint8_t target[32]);

/* Proof of work: the hash, read as a little-endian number, must be <= the target. */
bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32]);

#endif
