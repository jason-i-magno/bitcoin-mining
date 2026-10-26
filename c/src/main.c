/* Command-line entry point: c/miner --blocks 10 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mining.h"
#include "rpc.h"
#include "sha256.h"

static void usage(FILE *out) {
    fprintf(out,
            "usage: miner [options]\n"
            "\n"
            "Mine blocks on a local regtest bitcoind.\n"
            "\n"
            "  -n, --blocks N         number of blocks to mine (default: 1)\n"
            "      --address ADDR     where to pay block rewards (default: a new address from the node's wallet)\n"
            "  -t, --threads N        hashing threads (default: one per CPU)\n"
            "      --rpc-url URL      default: http://127.0.0.1:18443\n"
            "      --datadir DIR      bitcoind datadir, used to find the RPC cookie (default: ./data)\n"
            "      --rpc-user USER    use username/password auth instead of the cookie\n"
            "      --rpc-password PW\n"
            "      --benchmark SECS   measure hashrate for SECS seconds; needs no node\n"
            "  -h, --help\n");
}

static void die(const char *fmt, const char *detail) {
    fprintf(stderr, fmt, detail);
    fputc('\n', stderr);
    exit(1);
}

static long parse_positive(const char *s, const char *flag) {
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < 1) {
        die("%s must be a positive integer", flag);
    }
    return v;
}

static void benchmark(int threads, long seconds) {
    /* An impossible all-zero target, so every nonce is hashed. */
    block_header header = {.version = 0x20000000, .bits = 0x207fffff};
    uint8_t target[32] = {0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t hashes = 0, nonce = 0;
    double elapsed;
    do {
        search_result r = search(&header, target, nonce, nonce + (UINT64_C(1) << 24), threads);
        hashes += r.hashes;
        nonce = (nonce + (UINT64_C(1) << 24)) % NONCE_SPACE;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    } while (elapsed < (double)seconds);
    double rate = (double)hashes / elapsed;
    printf("%d thread(s), %s SHA-256: %.2f MH/s (%.2f MH/s per thread)\n", threads, sha256_implementation(),
           rate / 1e6, rate / 1e6 / threads);
}

/* Resolve the payout address to its scriptPubKey, asking the wallet for one if none was given. */
static size_t payout_script(rpc_client *rpc, const char *address, uint8_t script[MAX_SCRIPT_PUBKEY]) {
    json *generated = NULL;
    if (!address) {
        generated = rpc_call(rpc, "getnewaddress", "[]");
        if (!generated || generated->type != JSON_STRING) {
            die("could not get an address from the node's wallet (%s); pass --address instead", rpc->error);
        }
        address = generated->string;
    }

    buf_t params = {0};
    buf_u8(&params, '[');
    json_write_string(&params, address);
    buf_append_str(&params, "]");
    buf_u8(&params, '\0');
    json *info = rpc_call(rpc, "validateaddress", (const char *)params.data);
    buf_free(&params);
    if (!info) {
        die("%s", rpc->error);
    }

    const json *valid = json_get(info, "isvalid");
    const char *script_hex = json_get_string(info, "scriptPubKey");
    buf_t decoded = {0};
    if (!valid || !valid->boolean || !script_hex || !hex_decode_append(script_hex, &decoded) ||
        decoded.len > MAX_SCRIPT_PUBKEY) {
        die("not a valid address for this chain: %s", address);
    }
    memcpy(script, decoded.data, decoded.len);
    size_t len = decoded.len;
    printf("paying %s\n", address);

    buf_free(&decoded);
    json_free(info);
    json_free(generated);
    return len;
}

int main(int argc, char **argv) {
    long blocks = 1, threads = sysconf(_SC_NPROCESSORS_ONLN), benchmark_seconds = 0;
    const char *address = NULL, *rpc_url = "http://127.0.0.1:18443", *datadir = "data";
    const char *rpc_user = NULL, *rpc_password = "";

    enum { OPT_ADDRESS = 256, OPT_RPC_URL, OPT_DATADIR, OPT_RPC_USER, OPT_RPC_PASSWORD, OPT_BENCHMARK };
    static const struct option options[] = {
        {"blocks", required_argument, NULL, 'n'},
        {"threads", required_argument, NULL, 't'},
        {"address", required_argument, NULL, OPT_ADDRESS},
        {"rpc-url", required_argument, NULL, OPT_RPC_URL},
        {"datadir", required_argument, NULL, OPT_DATADIR},
        {"rpc-user", required_argument, NULL, OPT_RPC_USER},
        {"rpc-password", required_argument, NULL, OPT_RPC_PASSWORD},
        {"benchmark", required_argument, NULL, OPT_BENCHMARK},
        {"help", no_argument, NULL, 'h'},
        {0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "n:t:h", options, NULL)) != -1) {
        switch (opt) {
        case 'n': blocks = parse_positive(optarg, "--blocks"); break;
        case 't': threads = parse_positive(optarg, "--threads"); break;
        case OPT_ADDRESS: address = optarg; break;
        case OPT_RPC_URL: rpc_url = optarg; break;
        case OPT_DATADIR: datadir = optarg; break;
        case OPT_RPC_USER: rpc_user = optarg; break;
        case OPT_RPC_PASSWORD: rpc_password = optarg; break;
        case OPT_BENCHMARK: benchmark_seconds = parse_positive(optarg, "--benchmark"); break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 1;
        }
    }
    if (optind < argc) {
        usage(stderr);
        return 1;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (benchmark_seconds) {
        benchmark((int)threads, benchmark_seconds);
        return 0;
    }

    /* A closed connection should surface as a write error, not kill the process. */
    signal(SIGPIPE, SIG_IGN);

    rpc_client rpc;
    bool ready;
    if (rpc_user) {
        ready = rpc_init(&rpc, rpc_url, rpc_user, rpc_password);
    } else {
        char cookie[4096];
        snprintf(cookie, sizeof(cookie), "%s/regtest/.cookie", datadir);
        ready = rpc_init_cookie(&rpc, rpc_url, cookie);
    }
    json *info = ready ? rpc_call(&rpc, "getblockchaininfo", "[]") : NULL;
    const char *chain = json_get_string(info, "chain");
    if (!chain) {
        die("cannot reach bitcoind (%s). Start it with: scripts/regtest.sh start", rpc.error);
    }
    printf("Mining %ld block(s) on %s with %ld thread(s) and %s SHA-256, ", blocks, chain, threads,
           sha256_implementation());
    json_free(info);

    uint8_t script_pubkey[MAX_SCRIPT_PUBKEY];
    size_t script_pubkey_len = payout_script(&rpc, address, script_pubkey);

    for (long i = 0; i < blocks; i++) {
        mined_block block;
        char err[512];
        if (!mine_block(&rpc, script_pubkey, script_pubkey_len, (int)threads, &block, err, sizeof(err))) {
            die("%s", err);
        }
        printf("height %6u  %s  nonce=%u extranonce=%llu txs=%zu attempts=%llu (%.2fs)\n", block.height,
               block.hash, block.nonce, (unsigned long long)block.extranonce, block.tx_count,
               (unsigned long long)block.attempts, block.seconds);
        fflush(stdout);
    }
    return 0;
}
