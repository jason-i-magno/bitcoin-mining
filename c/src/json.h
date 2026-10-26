#ifndef JSON_H
#define JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "encoding.h"

/* A small JSON parser: enough for bitcoind's RPC replies. */

typedef enum { JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT } json_type;

typedef struct json {
    json_type type;
    bool boolean;
    double number;
    bool is_integer; /* the number had no fraction or exponent, and `integer` is exact */
    int64_t integer;
    char *string;
    char *key;          /* set on the members of an object */
    struct json *items; /* array elements or object members */
    size_t count;
} json;

/* Returns NULL if `text` is not a single valid JSON value. Free with json_free. */
json *json_parse(const char *text, size_t len);
void json_free(json *value);

/* Lookups return NULL when the key is missing or the value has another type. */
const json *json_get(const json *object, const char *key);
const char *json_get_string(const json *object, const char *key);
bool json_get_int(const json *object, const char *key, int64_t *out);

/* Append `s` as a quoted, escaped JSON string. */
void json_write_string(buf_t *out, const char *s);

#endif
