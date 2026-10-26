#include "encoding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buf_append(buf_t *b, const void *data, size_t len) {
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->len + len) {
            cap *= 2;
        }
        uint8_t *grown = realloc(b->data, cap);
        if (!grown) {
            perror("realloc");
            abort();
        }
        b->data = grown;
        b->cap = cap;
    }
    if (len) {
        memcpy(b->data + b->len, data, len);
        b->len += len;
    }
}

void buf_append_str(buf_t *b, const char *s) {
    buf_append(b, s, strlen(s));
}

void buf_u8(buf_t *b, uint8_t v) {
    buf_append(b, &v, 1);
}

void buf_le32(buf_t *b, uint32_t v) {
    uint8_t bytes[4] = {v, v >> 8, v >> 16, v >> 24};
    buf_append(b, bytes, sizeof(bytes));
}

void buf_le64(buf_t *b, uint64_t v) {
    buf_le32(b, (uint32_t)v);
    buf_le32(b, (uint32_t)(v >> 32));
}

void buf_free(buf_t *b) {
    free(b->data);
    *b = (buf_t){0};
}

void buf_compact_size(buf_t *b, uint64_t n) {
    if (n < 0xFD) {
        buf_u8(b, n);
    } else if (n <= 0xFFFF) {
        buf_u8(b, 0xFD);
        buf_u8(b, n);
        buf_u8(b, n >> 8);
    } else if (n <= 0xFFFFFFFF) {
        buf_u8(b, 0xFE);
        buf_le32(b, n);
    } else {
        buf_u8(b, 0xFF);
        buf_le64(b, n);
    }
}

void buf_push_data(buf_t *b, const uint8_t *data, size_t len) {
    if (len < 0x4C) {
        buf_u8(b, len);
    } else if (len <= 0xFF) {
        buf_u8(b, 0x4C); /* OP_PUSHDATA1 */
        buf_u8(b, len);
    } else if (len <= 0xFFFF) {
        buf_u8(b, 0x4D); /* OP_PUSHDATA2 */
        buf_u8(b, len);
        buf_u8(b, len >> 8);
    } else {
        buf_u8(b, 0x4E); /* OP_PUSHDATA4 */
        buf_le32(b, len);
    }
    buf_append(b, data, len);
}

void buf_push_int(buf_t *b, uint64_t n) {
    if (n == 0) {
        buf_u8(b, 0x00); /* OP_0 */
        return;
    }
    if (n <= 16) {
        buf_u8(b, 0x50 + n); /* OP_1 (0x51) .. OP_16 (0x60) */
        return;
    }
    /* Minimal little-endian. Script numbers are signed, so add a 0x00 byte
       if the top bit is set to keep the value positive. */
    uint8_t bytes[9];
    size_t len = 0;
    while (n) {
        bytes[len++] = n & 0xFF;
        n >>= 8;
    }
    if (bytes[len - 1] & 0x80) {
        bytes[len++] = 0x00;
    }
    buf_push_data(b, bytes, len);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_pair(const char *p) {
    int hi = hex_value(p[0]), lo = hex_value(p[1]);
    return hi < 0 || lo < 0 ? -1 : hi << 4 | lo;
}

bool hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != 2 * out_len) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int byte = hex_pair(hex + 2 * i);
        if (byte < 0) {
            return false;
        }
        out[i] = (uint8_t)byte;
    }
    return true;
}

bool hex_decode_append(const char *hex, buf_t *out) {
    size_t len = strlen(hex), start = out->len;
    if (len % 2) {
        return false;
    }
    for (size_t i = 0; i < len; i += 2) {
        int byte = hex_pair(hex + i);
        if (byte < 0) {
            out->len = start;
            return false;
        }
        buf_u8(out, (uint8_t)byte);
    }
    return true;
}

void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

void hex_encode_append(const uint8_t *data, size_t len, buf_t *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        uint8_t pair[2] = {digits[data[i] >> 4], digits[data[i] & 0x0F]};
        buf_append(out, pair, 2);
    }
}

bool from_display_hex(const char *hex, uint8_t out[32]) {
    uint8_t bytes[32];
    if (!hex_decode(hex, bytes, 32)) {
        return false;
    }
    for (int i = 0; i < 32; i++) {
        out[i] = bytes[31 - i];
    }
    return true;
}

void to_display_hex(const uint8_t hash[32], char out[65]) {
    uint8_t reversed[32];
    for (int i = 0; i < 32; i++) {
        reversed[i] = hash[31 - i];
    }
    hex_encode(reversed, 32, out);
}

void bits_to_target(uint32_t bits, uint8_t target[32]) {
    int exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007FFFFF;
    memset(target, 0, 32);
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        exponent = 3;
    }
    for (int i = 0; i < 3; i++) {
        int pos = exponent - 3 + i;
        if (pos < 32) {
            target[pos] = (mantissa >> (8 * i)) & 0xFF;
        }
    }
}

bool hash_meets_target(const uint8_t hash[32], const uint8_t target[32]) {
    for (int i = 31; i >= 0; i--) {
        if (hash[i] != target[i]) {
            return hash[i] < target[i];
        }
    }
    return true;
}
