#include "json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64

typedef struct {
    const char *p;
    const char *end;
    int depth;
} parser;

static bool parse_value(parser *ps, json *out);

static void free_contents(json *v) {
    free(v->string);
    free(v->key);
    for (size_t i = 0; i < v->count; i++) {
        free_contents(&v->items[i]);
    }
    free(v->items);
}

void json_free(json *value) {
    if (value) {
        free_contents(value);
        free(value);
    }
}

static void skip_whitespace(parser *ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) {
        ps->p++;
    }
}

static bool consume(parser *ps, const char *word) {
    size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n) != 0) {
        return false;
    }
    ps->p += n;
    return true;
}

static bool parse_hex4(parser *ps, uint32_t *out) {
    if (ps->end - ps->p < 4) {
        return false;
    }
    *out = 0;
    for (int i = 0; i < 4; i++) {
        char c = *ps->p++;
        int v = c >= '0' && c <= '9' ? c - '0'
              : c >= 'a' && c <= 'f' ? c - 'a' + 10
              : c >= 'A' && c <= 'F' ? c - 'A' + 10
              : -1;
        if (v < 0) {
            return false;
        }
        *out = *out << 4 | (uint32_t)v;
    }
    return true;
}

static void append_utf8(buf_t *b, uint32_t cp) {
    if (cp < 0x80) {
        buf_u8(b, cp);
    } else if (cp < 0x800) {
        buf_u8(b, 0xC0 | cp >> 6);
        buf_u8(b, 0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        buf_u8(b, 0xE0 | cp >> 12);
        buf_u8(b, 0x80 | (cp >> 6 & 0x3F));
        buf_u8(b, 0x80 | (cp & 0x3F));
    } else {
        buf_u8(b, 0xF0 | cp >> 18);
        buf_u8(b, 0x80 | (cp >> 12 & 0x3F));
        buf_u8(b, 0x80 | (cp >> 6 & 0x3F));
        buf_u8(b, 0x80 | (cp & 0x3F));
    }
}

static bool parse_string(parser *ps, char **out) {
    if (!consume(ps, "\"")) {
        return false;
    }
    buf_t b = {0};
    while (ps->p < ps->end && *ps->p != '"') {
        unsigned char c = (unsigned char)*ps->p++;
        if (c < 0x20) {
            goto fail; /* control characters must be escaped */
        }
        if (c != '\\') {
            buf_u8(&b, c);
            continue;
        }
        if (ps->p >= ps->end) {
            goto fail;
        }
        switch (*ps->p++) {
        case '"': buf_u8(&b, '"'); break;
        case '\\': buf_u8(&b, '\\'); break;
        case '/': buf_u8(&b, '/'); break;
        case 'b': buf_u8(&b, '\b'); break;
        case 'f': buf_u8(&b, '\f'); break;
        case 'n': buf_u8(&b, '\n'); break;
        case 'r': buf_u8(&b, '\r'); break;
        case 't': buf_u8(&b, '\t'); break;
        case 'u': {
            uint32_t cp, low;
            if (!parse_hex4(ps, &cp)) {
                goto fail;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                /* A high surrogate must be followed by a low one; together they encode one code point. */
                if (!consume(ps, "\\u") || !parse_hex4(ps, &low) || low < 0xDC00 || low > 0xDFFF) {
                    goto fail;
                }
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                goto fail;
            }
            append_utf8(&b, cp);
            break;
        }
        default:
            goto fail;
        }
    }
    if (!consume(ps, "\"")) {
        goto fail;
    }
    buf_u8(&b, '\0');
    *out = (char *)b.data;
    return true;

fail:
    buf_free(&b);
    return false;
}

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool parse_number(parser *ps, json *out) {
    const char *start = ps->p;
    bool integer = true;
    if (ps->p < ps->end && *ps->p == '-') {
        ps->p++;
    }
    if (ps->p >= ps->end || !is_digit(*ps->p)) {
        return false;
    }
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c == '.' || c == 'e' || c == 'E') {
            integer = false;
        } else if (!is_digit(c) && c != '+' && c != '-') {
            break;
        }
        ps->p++;
    }

    /* strtod/strtoll need a NUL-terminated copy; they also validate what the loop above skimmed. */
    char token[64];
    size_t len = (size_t)(ps->p - start);
    if (len >= sizeof(token)) {
        return false;
    }
    memcpy(token, start, len);
    token[len] = '\0';

    char *end;
    out->type = JSON_NUMBER;
    out->number = strtod(token, &end);
    if (*end != '\0') {
        return false;
    }
    if (integer) {
        errno = 0;
        out->integer = strtoll(token, &end, 10);
        out->is_integer = *end == '\0' && errno == 0;
    }
    return true;
}

/* Grow `items` to the next power of two when `count` reaches one. */
static json *add_item(json *container) {
    size_t n = container->count;
    if (n == 0 || (n & (n - 1)) == 0) {
        json *grown = realloc(container->items, (n ? 2 * n : 1) * sizeof(json));
        if (!grown) {
            perror("realloc");
            abort();
        }
        container->items = grown;
    }
    json *item = &container->items[container->count++];
    *item = (json){0};
    return item;
}

static bool parse_container(parser *ps, json *out, const char *close, bool is_object) {
    out->type = is_object ? JSON_OBJECT : JSON_ARRAY;
    ps->p++; /* the opening bracket */
    skip_whitespace(ps);
    if (consume(ps, close)) {
        return true;
    }
    for (;;) {
        skip_whitespace(ps);
        char *key = NULL;
        if (is_object) {
            if (!parse_string(ps, &key)) {
                return false;
            }
            skip_whitespace(ps);
            if (!consume(ps, ":")) {
                free(key);
                return false;
            }
        }
        json *item = add_item(out);
        item->key = key;
        if (!parse_value(ps, item)) {
            return false;
        }
        skip_whitespace(ps);
        if (consume(ps, ",")) {
            continue;
        }
        return consume(ps, close);
    }
}

static bool parse_value(parser *ps, json *out) {
    if (++ps->depth > MAX_DEPTH) {
        return false;
    }
    skip_whitespace(ps);
    bool ok;
    if (ps->p >= ps->end) {
        ok = false;
    } else if (*ps->p == '{') {
        ok = parse_container(ps, out, "}", true);
    } else if (*ps->p == '[') {
        ok = parse_container(ps, out, "]", false);
    } else if (*ps->p == '"') {
        out->type = JSON_STRING;
        ok = parse_string(ps, &out->string);
    } else if (consume(ps, "true")) {
        out->type = JSON_BOOL;
        out->boolean = true;
        ok = true;
    } else if (consume(ps, "false")) {
        out->type = JSON_BOOL;
        ok = true;
    } else if (consume(ps, "null")) {
        out->type = JSON_NULL;
        ok = true;
    } else {
        ok = parse_number(ps, out);
    }
    ps->depth--;
    return ok;
}

json *json_parse(const char *text, size_t len) {
    parser ps = {text, text + len, 0};
    json *root = calloc(1, sizeof(json));
    if (!root) {
        return NULL;
    }
    if (parse_value(&ps, root)) {
        skip_whitespace(&ps);
        if (ps.p == ps.end) {
            return root;
        }
    }
    json_free(root);
    return NULL;
}

const json *json_get(const json *object, const char *key) {
    if (!object || object->type != JSON_OBJECT) {
        return NULL;
    }
    for (size_t i = 0; i < object->count; i++) {
        if (strcmp(object->items[i].key, key) == 0) {
            return &object->items[i];
        }
    }
    return NULL;
}

const char *json_get_string(const json *object, const char *key) {
    const json *v = json_get(object, key);
    return v && v->type == JSON_STRING ? v->string : NULL;
}

bool json_get_int(const json *object, const char *key, int64_t *out) {
    const json *v = json_get(object, key);
    if (!v || v->type != JSON_NUMBER || !v->is_integer) {
        return false;
    }
    *out = v->integer;
    return true;
}

void json_write_string(buf_t *out, const char *s) {
    buf_u8(out, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            buf_u8(out, '\\');
            buf_u8(out, c);
        } else if (c < 0x20) {
            char escaped[7];
            snprintf(escaped, sizeof(escaped), "\\u%04x", c);
            buf_append_str(out, escaped);
        } else {
            buf_u8(out, c);
        }
    }
    buf_u8(out, '"');
}
