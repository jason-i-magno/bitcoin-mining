/* Unit tests: no node needed. Vectors are from mainnet, so passing means our
   encodings agree with Bitcoin itself. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block.h"
#include "encoding.h"
#include "gpu.h"
#include "json.h"
#include "mining.h"
#include "rpc.h"
#include "sha256.h"
#include "tx.h"

static int checks, failures;

#define CHECK(cond)                                                              \
    do {                                                                         \
        checks++;                                                                \
        if (!(cond)) {                                                           \
            failures++;                                                          \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

#define CHECK_HEX(data, len, expected) check_hex(__FILE__, __LINE__, data, len, expected)

static void check_hex(const char *file, int line, const uint8_t *data, size_t len, const char *expected) {
    char *actual = malloc(2 * len + 1);
    hex_encode(data, len, actual);
    checks++;
    if (strcmp(actual, expected) != 0) {
        failures++;
        fprintf(stderr, "%s:%d: expected %s\n%*s     got %s\n", file, line, expected, (int)strlen(file), "", actual);
    }
    free(actual);
}

/* A 256-bit little-endian number as big-endian hex, the way targets are usually written. */
static void check_target(uint32_t bits, const char *expected, int line) {
    uint8_t target[32], be[32];
    bits_to_target(bits, target);
    for (int i = 0; i < 32; i++) {
        be[i] = target[31 - i];
    }
    check_hex(__FILE__, line, be, 32, expected);
}

static void test_sha256(void) {
    uint8_t digest[32];
    sha256("", 0, digest);
    CHECK_HEX(digest, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sha256("abc", 3, digest);
    CHECK_HEX(digest, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *two_blocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(two_blocks, strlen(two_blocks), digest);
    CHECK_HEX(digest, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* One million 'a's, fed in uneven pieces to exercise buffering across blocks. */
    sha256_ctx ctx;
    sha256_init(&ctx);
    char as[1000];
    memset(as, 'a', sizeof(as));
    size_t fed = 0;
    for (size_t piece = 1; fed < 1000000; piece = piece % 997 + 1) {
        size_t n = piece < 1000000 - fed ? piece : 1000000 - fed;
        sha256_update(&ctx, as, n);
        fed += n;
    }
    sha256_final(&ctx, digest);
    CHECK_HEX(digest, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_compact_size(void) {
    struct { uint64_t n; const char *hex; } cases[] = {
        {0, "00"},
        {0xFC, "fc"},
        {0xFD, "fdfd00"},
        {0xFFFF, "fdffff"},
        {0x10000, "fe00000100"},
        {0xFFFFFFFF, "feffffffff"},
        {0x100000000, "ff0000000001000000"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        buf_t b = {0};
        buf_compact_size(&b, cases[i].n);
        CHECK_HEX(b.data, b.len, cases[i].hex);
        buf_free(&b);
    }
}

static void test_script_pushes(void) {
    uint8_t data[76];
    memset(data, 0xab, sizeof(data));
    buf_t b = {0};
    buf_push_data(&b, data, 0);
    CHECK_HEX(b.data, b.len, "00");
    b.len = 0;
    buf_push_data(&b, data, 75);
    CHECK(b.len == 76 && b.data[0] == 0x4b);
    b.len = 0;
    buf_push_data(&b, data, 76);
    CHECK(b.len == 78 && b.data[0] == 0x4c && b.data[1] == 76);

    /* Must match Bitcoin Core's `CScript() << n`, which BIP34 compares byte for byte. */
    struct { uint64_t n; const char *hex; } cases[] = {
        {1, "51"},        /* OP_1 */
        {16, "60"},       /* OP_16 */
        {17, "0111"},
        {127, "017f"},
        {128, "028000"},  /* 0x80 alone would read as negative zero */
        {255, "02ff00"},
        {256, "020001"},
        {32767, "02ff7f"},
        {32768, "03008000"},
        {500000, "0320a107"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        b.len = 0;
        buf_push_int(&b, cases[i].n);
        CHECK_HEX(b.data, b.len, cases[i].hex);
    }
    buf_free(&b);
}

static void test_targets(void) {
    check_target(0x1D00FFFF, "00000000ffff0000000000000000000000000000000000000000000000000000", __LINE__);
    /* Regtest's target is about half of all hashes, so ~2 attempts per block. */
    check_target(0x207FFFFF, "7fffff0000000000000000000000000000000000000000000000000000000000", __LINE__);
    check_target(0x1B0404CB, "00000000000404cb000000000000000000000000000000000000000000000000", __LINE__);

    uint8_t target[32] = {0}, hash[32] = {0};
    target[31] = 0x10;
    hash[31] = 0x10;
    CHECK(hash_meets_target(hash, target)); /* equal counts */
    hash[0] = 1;
    CHECK(!hash_meets_target(hash, target));
    hash[31] = 0x0f;
    CHECK(hash_meets_target(hash, target));
}

static const char GENESIS_COINBASE_HEX[] =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
    "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72"
    "206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff"
    "0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f"
    "61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
static const char GENESIS_TXID[] = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

static void test_genesis_coinbase(void) {
    buf_t raw = {0};
    CHECK(hex_decode_append(GENESIS_COINBASE_HEX, &raw));
    coinbase_tx cb = {.version = 1, .script_sig_len = 0x4d, .value = 50 * 100000000ULL, .script_pubkey_len = 0x43};
    memcpy(cb.script_sig, raw.data + 42, 0x4d);
    memcpy(cb.script_pubkey, raw.data + raw.len - 4 - 0x43, 0x43);

    buf_t ours = {0};
    coinbase_serialize(&cb, true, &ours);
    CHECK(ours.len == raw.len && memcmp(ours.data, raw.data, raw.len) == 0);

    uint8_t txid[32];
    char txid_hex[65];
    coinbase_txid(&cb, txid);
    to_display_hex(txid, txid_hex);
    CHECK(strcmp(txid_hex, GENESIS_TXID) == 0);
    buf_free(&raw);
    buf_free(&ours);
}

static const uint8_t P2WPKH[22] = {0x00, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

static void test_coinbase(void) {
    uint8_t extranonce[8] = {0};
    coinbase_tx cb;
    CHECK(coinbase_build(&cb, 1, extranonce, 8, 50, P2WPKH, sizeof(P2WPKH), NULL, DEFAULT_COINBASE_TAG));
    CHECK(cb.script_sig[0] == 0x51);
    CHECK(coinbase_build(&cb, 500000, extranonce, 8, 50, P2WPKH, sizeof(P2WPKH), NULL, DEFAULT_COINBASE_TAG));
    CHECK_HEX(cb.script_sig, 4, "0320a107");

    /* Without a commitment there is no witness, so both serializations match. */
    buf_t full = {0}, stripped = {0};
    coinbase_serialize(&cb, true, &full);
    coinbase_serialize(&cb, false, &stripped);
    CHECK(full.len == stripped.len && memcmp(full.data, stripped.data, full.len) == 0);

    uint8_t commitment[32];
    for (int i = 0; i < 32; i++) {
        commitment[i] = (uint8_t)i;
    }
    CHECK(coinbase_build(&cb, 1, extranonce, 8, 50, P2WPKH, sizeof(P2WPKH), commitment, DEFAULT_COINBASE_TAG));
    full.len = stripped.len = 0;
    coinbase_serialize(&cb, true, &full);
    coinbase_serialize(&cb, false, &stripped);
    /* The segwit marker appears in the full serialization but not in what the txid hashes. */
    CHECK(full.data[4] == 0x00 && full.data[5] == 0x01);
    CHECK(!(stripped.data[4] == 0x00 && stripped.data[5] == 0x01));
    /* Full = stripped + marker/flag (2) + witness count, item length, 32-byte reserved value (34). */
    CHECK(full.len == stripped.len + 36);
    uint8_t script[WITNESS_COMMITMENT_SCRIPT_SIZE];
    witness_commitment_script(commitment, script);
    CHECK_HEX(script, 6, "6a24aa21a9ed");
    CHECK(memcmp(stripped.data + stripped.len - 4 - sizeof(script), script, sizeof(script)) == 0);

    uint8_t a[32], b[32];
    coinbase_txid(&cb, a);
    extranonce[0] = 1;
    CHECK(coinbase_build(&cb, 1, extranonce, 8, 50, P2WPKH, sizeof(P2WPKH), commitment, DEFAULT_COINBASE_TAG));
    coinbase_txid(&cb, b);
    CHECK(memcmp(a, b, 32) != 0); /* the extranonce changes the txid */

    char long_tag[101];
    memset(long_tag, 'x', 100);
    long_tag[100] = '\0';
    CHECK(!coinbase_build(&cb, 1, extranonce, 8, 50, P2WPKH, sizeof(P2WPKH), NULL, long_tag));
    buf_free(&full);
    buf_free(&stripped);
}

static block_header genesis_header(void) {
    block_header h = {.version = 1, .timestamp = 1231006505, .bits = 0x1D00FFFF, .nonce = 2083236893};
    from_display_hex(GENESIS_TXID, h.merkle_root);
    return h;
}

static void test_header(void) {
    block_header h = genesis_header();
    uint8_t hash[32];
    char hex[65];
    header_hash(&h, hash);
    to_display_hex(hash, hex);
    CHECK(strcmp(hex, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") == 0);
}

static void test_merkle(void) {
    uint8_t one[1][32], root[32];
    for (int i = 0; i < 32; i++) {
        one[0][i] = (uint8_t)i;
    }
    merkle_root((const uint8_t(*)[32])one, 1, root);
    CHECK(memcmp(root, one[0], 32) == 0);

    const char *block_100000[] = {
        "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
        "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
        "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
        "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
    };
    uint8_t txids[4][32];
    for (int i = 0; i < 4; i++) {
        CHECK(from_display_hex(block_100000[i], txids[i]));
    }
    char hex[65];
    merkle_root((const uint8_t(*)[32])txids, 4, root);
    to_display_hex(root, hex);
    CHECK(strcmp(hex, "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766") == 0);

    /* An odd level duplicates its last hash: root(a, b, c) = H(H(a + b) + H(c + c)). */
    uint8_t abc[3][32], ab[64], cc[64], level[64], expected[32];
    for (int i = 0; i < 3; i++) {
        memset(abc[i], i, 32);
    }
    memcpy(ab, abc[0], 32);
    memcpy(ab + 32, abc[1], 32);
    memcpy(cc, abc[2], 32);
    memcpy(cc + 32, abc[2], 32);
    sha256d(ab, 64, level);
    sha256d(cc, 64, level + 32);
    sha256d(level, 64, expected);
    merkle_root((const uint8_t(*)[32])abc, 3, root);
    CHECK(memcmp(root, expected, 32) == 0);
}

static void test_witness_commitment(void) {
    /* The value Bitcoin Core puts in default_witness_commitment for an empty block. */
    uint8_t commitment[32];
    witness_commitment(NULL, 0, commitment);
    CHECK_HEX(commitment, 32, "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");
}

static void test_json(void) {
    const char *text = " {\"a\": [1, -2, 3.5, true, false, null], \"s\": \"q\\\"\\\\\\n\\u00e9\\ud83d\\ude00\","
                       " \"big\": 2100000000000000, \"o\": {}} ";
    json *v = json_parse(text, strlen(text));
    CHECK(v && v->type == JSON_OBJECT && v->count == 4);
    const json *a = json_get(v, "a");
    CHECK(a && a->type == JSON_ARRAY && a->count == 6);
    if (a && a->count == 6) {
        CHECK(a->items[0].is_integer && a->items[0].integer == 1);
        CHECK(a->items[1].is_integer && a->items[1].integer == -2);
        CHECK(!a->items[2].is_integer && a->items[2].number == 3.5);
        CHECK(a->items[3].type == JSON_BOOL && a->items[3].boolean);
        CHECK(a->items[4].type == JSON_BOOL && !a->items[4].boolean);
        CHECK(a->items[5].type == JSON_NULL);
    }
    CHECK(json_get_string(v, "s") && strcmp(json_get_string(v, "s"), "q\"\\\n\xc3\xa9\xf0\x9f\x98\x80") == 0);
    int64_t big;
    CHECK(json_get_int(v, "big", &big) && big == 2100000000000000);
    CHECK(json_get(v, "o") && json_get(v, "o")->type == JSON_OBJECT);
    CHECK(json_get(v, "missing") == NULL && json_get_string(v, "a") == NULL);
    json_free(v);

    const char *invalid[] = {"", "[1,]", "{\"a\" 1}", "\"unterminated", "[1] x", "{\"a\":1,}", "nul", "\"\\ud83d\""};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        json *bad = json_parse(invalid[i], strlen(invalid[i]));
        CHECK(bad == NULL);
        json_free(bad);
    }

    /* Too big for int64: still a number, but not an exact integer. */
    json *huge = json_parse("99999999999999999999999", 23);
    CHECK(huge && huge->type == JSON_NUMBER && !huge->is_integer);
    json_free(huge);

    buf_t out = {0};
    json_write_string(&out, "a\"b\\c\n");
    buf_u8(&out, '\0');
    CHECK(strcmp((const char *)out.data, "\"a\\\"b\\\\c\\u000a\"") == 0);
    buf_free(&out);
}

static void test_dechunk(void) {
    const char *body = "4\r\nWiki\r\n6;ext=1\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n";
    buf_t out = {0};
    CHECK(http_dechunk(body, strlen(body), &out));
    buf_u8(&out, '\0');
    CHECK(strcmp((const char *)out.data, "Wikipedia in \r\n\r\nchunks.") == 0);
    out.len = 0;
    CHECK(!http_dechunk("5\r\nabc", 7, &out));
    buf_free(&out);
}

/* Shaped like bitcoind's getblocktemplate reply for block 1 on a fresh regtest chain. */
static const char REGTEST_TEMPLATE[] =
    "{\"version\": 536870912,"
    " \"previousblockhash\": \"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206\","
    " \"transactions\": [],"
    " \"coinbasevalue\": 5000000000,"
    " \"target\": \"7fffff0000000000000000000000000000000000000000000000000000000000\","
    " \"curtime\": 1700000000,"
    " \"bits\": \"207fffff\","
    " \"height\": 1,"
    " \"default_witness_commitment\": "
    "\"6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9\"}";

static void test_build_candidate(void) {
    json *t = json_parse(REGTEST_TEMPLATE, strlen(REGTEST_TEMPLATE));
    CHECK(t != NULL);
    candidate c;
    char err[256];
    CHECK(build_candidate(t, P2WPKH, sizeof(P2WPKH), 0, &c, err, sizeof(err)));
    CHECK(c.header.version == 0x20000000);
    CHECK(c.header.bits == 0x207FFFFF);
    CHECK(c.height == 1 && c.tx_count == 0);
    char prev[65];
    to_display_hex(c.header.prev_block, prev);
    CHECK(strcmp(prev, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206") == 0);
    /* With only a coinbase, the merkle root is the coinbase txid. */
    uint8_t txid[32];
    coinbase_txid(&c.coinbase, txid);
    CHECK(memcmp(c.header.merkle_root, txid, 32) == 0);

    search_result r = search(&c.header, c.target, 0, 1000, 1);
    CHECK(r.found && r.hashes == (uint64_t)r.nonce + 1);
    c.header.nonce = r.nonce;
    buf_t block = {0};
    candidate_serialize(&c, &block);
    CHECK(block.data[80] == 1); /* transaction count: just the coinbase */
    uint8_t hash[32];
    sha256d(block.data, HEADER_SIZE, hash);
    CHECK(hash_meets_target(hash, c.target));
    buf_free(&block);
    candidate_free(&c);

    /* A node commitment that disagrees with ours is refused. */
    char *tampered = strdup(REGTEST_TEMPLATE);
    char *commitment = strstr(tampered, "e2f61c3f");
    commitment[0] = 'f';
    json *bad = json_parse(tampered, strlen(tampered));
    CHECK(!build_candidate(bad, P2WPKH, sizeof(P2WPKH), 0, &c, err, sizeof(err)));
    CHECK(strstr(err, "witness commitment") != NULL);
    json_free(bad);
    free(tampered);
    json_free(t);
}

/* The nonce in [lo, hi) with the smallest header hash, computed the slow way, and that
   hash. As a target, it is met by that nonce alone. */
static uint32_t smallest_hash(block_header h, uint64_t lo, uint64_t hi, uint8_t smallest[32]) {
    uint8_t hash[32];
    uint32_t smallest_nonce = 0;
    for (uint64_t nonce = lo; nonce < hi; nonce++) {
        h.nonce = (uint32_t)nonce;
        header_hash(&h, hash);
        if (nonce == lo || hash_meets_target(hash, smallest)) {
            memcpy(smallest, hash, 32);
            smallest_nonce = h.nonce;
        }
    }
    return smallest_nonce;
}

/* The fast path (midstate, precomputed padding, early rejection) must agree with plain
   sha256d. With the target set to the smallest hash among some nonces, search must find
   exactly that nonce, which also exercises the full comparison when the top 32 bits
   are equal. */
static void test_search_matches_reference(void) {
    block_header h = genesis_header();
    const uint32_t n = 5000;
    uint8_t best[32];
    uint32_t best_nonce = smallest_hash(h, 0, n, best);
    for (int threads = 1; threads <= 4; threads++) {
        search_result r = search(&h, best, 0, n, threads);
        CHECK(r.found && r.nonce == best_nonce);
    }

    uint8_t impossible[32] = {0};
    search_result r = search(&h, impossible, 0, n, 3);
    CHECK(!r.found && r.hashes == n);
}

/* main runs every test on the fastest implementation. Repeat the hashing tests on the
   portable one, so a CPU with SHA-NI still checks the code other CPUs would run. */
static void test_generic_compress(void) {
    sha256_use(sha256_compress_generic);
    CHECK(strcmp(sha256_implementation(), "generic") == 0);
    test_sha256();
    test_search_matches_reference();
    sha256_use(NULL);
}

static uint32_t xorshift(uint64_t *x) {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    return (uint32_t)(*x >> 32);
}

/* Compare SHA-NI with the portable code on pseudo-random states and blocks. */
static void test_shani_matches_generic(void) {
#ifdef SHA256_HAVE_SHANI
    if (!sha256_shani_supported()) {
        printf("this CPU has no SHA-NI, so only the generic SHA-256 was tested\n");
        return;
    }
    CHECK(strcmp(sha256_implementation(), "SHA-NI") == 0);
    uint64_t x = UINT64_C(0x9E3779B97F4A7C15);
    int mismatches = 0;
    for (int i = 0; i < 10000; i++) {
        uint32_t a[8], b[8], block[16];
        for (int j = 0; j < 8; j++) {
            a[j] = b[j] = xorshift(&x);
        }
        for (int j = 0; j < 16; j++) {
            block[j] = xorshift(&x);
        }
        sha256_compress_generic(a, block);
        sha256_compress_shani(b, block);
        mismatches += memcmp(a, b, sizeof(a)) != 0;
    }
    CHECK(mismatches == 0);
#endif
}

#ifdef HAVE_OPENCL
static search_result run_gpu(gpu_device *gpu, const block_header *h, const uint8_t target[32], uint64_t lo,
                             uint64_t hi) {
    search_result r = {0};
    char err[512] = "";
    bool ok = gpu_search(gpu, h, target, lo, hi, &r, err, sizeof(err));
    CHECK(ok);
    if (!ok) {
        fprintf(stderr, "  gpu_search: %s\n", err);
    }
    return r;
}

/* The GPU must find the same nonces as the CPU: the only one that meets the smallest
   hash in a range as its target, and the first of several that meet an easier one.
   Launches of 1000 nonces put answers in later launches and end mid-work-group, and a
   range at the top of the nonce space checks nonces near 2^32. */
static void test_gpu_search(void) {
    char err[8192];
    gpu_device *gpu = gpu_open(err, sizeof(err));
    if (!gpu) {
        printf("no usable GPU, so the GPU search was not tested: %s\n", err);
        return;
    }
    block_header h = genesis_header();
    const uint32_t n = 5000;
    const uint64_t starts[] = {0, NONCE_SPACE - n};
    const uint32_t batches[] = {GPU_BATCH, 1000};

    /* About 1 hash in 1000 is below 2^32/1000 * 2^224, so 5000 nonces hold several. */
    uint8_t easy[32], impossible[32] = {0};
    memset(easy, 0xff, 28);
    memcpy(easy + 28, (const uint8_t[]){0x37, 0x89, 0x41, 0x00}, 4);

    for (int s = 0; s < 2; s++) {
        uint64_t lo = starts[s], hi = lo + n;
        uint8_t smallest[32];
        uint32_t smallest_nonce = smallest_hash(h, lo, hi, smallest);
        search_result first = search(&h, easy, lo, hi, 1);
        CHECK(first.found);
        for (int b = 0; b < 2; b++) {
            gpu_set_batch(gpu, batches[b]);
            search_result r = run_gpu(gpu, &h, smallest, lo, hi);
            CHECK(r.found && r.nonce == smallest_nonce);
            r = run_gpu(gpu, &h, easy, lo, hi);
            CHECK(r.found && r.nonce == first.nonce);
            r = run_gpu(gpu, &h, impossible, lo, hi);
            CHECK(!r.found && r.hashes == n);
        }
    }
    gpu_close(gpu);
}
#endif

int main(void) {
    test_sha256();
    test_compact_size();
    test_script_pushes();
    test_targets();
    test_genesis_coinbase();
    test_coinbase();
    test_header();
    test_merkle();
    test_witness_commitment();
    test_json();
    test_dechunk();
    test_build_candidate();
    test_search_matches_reference();
    test_generic_compress();
    test_shani_matches_generic();
#ifdef HAVE_OPENCL
    test_gpu_search();
#endif

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
