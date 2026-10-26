#ifndef RPC_H
#define RPC_H

#include <stdbool.h>

#include "encoding.h"
#include "json.h"

/* Minimal JSON-RPC client for bitcoind: one HTTP/1.1 request per connection. */
typedef struct {
    char host[256];
    char port[8];
    char path[256];
    char auth[512];  /* "Basic <base64(user:password)>" */
    char error[512]; /* why the last failed call or init failed */
} rpc_client;

/* `url` looks like http://127.0.0.1:18443 or http://host:port/wallet/name. */
bool rpc_init(rpc_client *rpc, const char *url, const char *user, const char *password);

/* Authenticate with the cookie file bitcoind writes to its datadir on startup. */
bool rpc_init_cookie(rpc_client *rpc, const char *url, const char *cookie_path);

/* Call `method` with `params`, a JSON array literal such as "[]". Returns the reply's
   "result" (JSON null for calls like submitblock that succeed silently), which the
   caller frees with json_free. Returns NULL with rpc->error set on failure. */
json *rpc_call(rpc_client *rpc, const char *method, const char *params);

/* Decode an HTTP chunked transfer-encoded body. Exposed for tests. */
bool http_dechunk(const char *body, size_t len, buf_t *out);

#endif
