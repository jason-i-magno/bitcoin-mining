/* OpenCL kernel for the GPU nonce search; gpu.c compiles and launches it. Each work
   item tries one nonce, with the same shortcuts as search_worker in mining.c: it
   resumes from the header's midstate, and the SHA-256 padding words are constants.

   Everything is written out without loops or arrays. GPU compilers don't reliably
   unroll a 64-round loop, and arrays indexed inside one end up in slow scratch memory
   instead of registers, which made an earlier, loop-based version 5x slower. The
   state and message blocks are passed as vector values (uint8, uint16) for the same
   reason. */

#define ROTR(x, n) rotate((x), 32u - (n))
#define BSWAP32(x) as_uint(as_uchar4(x).s3210)

#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* One round. Rather than shift all eight working variables along, each round only
   updates d and h, and the next round is called with the roles rotated by one.
   bitselect(x, y, m) takes y where m is 1: Ch picks f or g by e, and Maj is a where
   a and c agree, b otherwise. `w` is evaluated once, so it can be a SCHEDULE. */
#define ROUND(a, b, c, d, e, f, g, h, k, w)                         \
    do {                                                            \
        uint t1 = (h) + S1(e) + bitselect(g, f, e) + (k) + (w);     \
        (d) += t1;                                                  \
        (h) = t1 + S0(a) + bitselect(a, b, (a) ^ (c));              \
    } while (0)

/* Eight rounds from round i; afterwards the roles are back where they started. */
#define ROUNDS8(i, x0, x1, x2, x3, x4, x5, x6, x7) \
    ROUND(a, b, c, d, e, f, g, h, K[(i) + 0], x0);  \
    ROUND(h, a, b, c, d, e, f, g, K[(i) + 1], x1);  \
    ROUND(g, h, a, b, c, d, e, f, K[(i) + 2], x2);  \
    ROUND(f, g, h, a, b, c, d, e, K[(i) + 3], x3);  \
    ROUND(e, f, g, h, a, b, c, d, K[(i) + 4], x4);  \
    ROUND(d, e, f, g, h, a, b, c, K[(i) + 5], x5);  \
    ROUND(c, d, e, f, g, h, a, b, K[(i) + 6], x6);  \
    ROUND(b, c, d, e, f, g, h, a, K[(i) + 7], x7)

/* W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16], computed in place of W[t-16],
   which is the oldest of the 16 words kept. */
#define SCHEDULE(w16, w15, w7, w2) ((w16) += s0(w15) + (w7) + s1(w2))

/* Rounds i to i+15 for i >= 16, each computing its message word first. */
#define ROUNDS16(i)                                                                                    \
    ROUNDS8(i, SCHEDULE(w0, w1, w9, w14), SCHEDULE(w1, w2, w10, w15), SCHEDULE(w2, w3, w11, w0),       \
            SCHEDULE(w3, w4, w12, w1), SCHEDULE(w4, w5, w13, w2), SCHEDULE(w5, w6, w14, w3),           \
            SCHEDULE(w6, w7, w15, w4), SCHEDULE(w7, w8, w0, w5));                                      \
    ROUNDS8((i) + 8, SCHEDULE(w8, w9, w1, w6), SCHEDULE(w9, w10, w2, w7), SCHEDULE(w10, w11, w3, w8),  \
            SCHEDULE(w11, w12, w4, w9), SCHEDULE(w12, w13, w5, w10), SCHEDULE(w13, w14, w6, w11),      \
            SCHEDULE(w14, w15, w7, w12), SCHEDULE(w15, w0, w8, w13))

static inline uint8 compress(uint8 state, uint16 m) {
    uint a = state.s0, b = state.s1, c = state.s2, d = state.s3;
    uint e = state.s4, f = state.s5, g = state.s6, h = state.s7;
    uint w0 = m.s0, w1 = m.s1, w2 = m.s2, w3 = m.s3, w4 = m.s4, w5 = m.s5, w6 = m.s6, w7 = m.s7;
    uint w8 = m.s8, w9 = m.s9, w10 = m.sa, w11 = m.sb, w12 = m.sc, w13 = m.sd, w14 = m.se, w15 = m.sf;

    ROUNDS8(0, w0, w1, w2, w3, w4, w5, w6, w7);
    ROUNDS8(8, w8, w9, w10, w11, w12, w13, w14, w15);
    ROUNDS16(16);
    ROUNDS16(32);
    ROUNDS16(48);

    return state + (uint8)(a, b, c, d, e, f, g, h);
}

/* Compare as 256-bit little-endian numbers, most significant limb first. Digest word
   k, byte-swapped, is limb k, so nearly every hash is decided by digest[7] alone. */
static inline bool meets_target(uint8 digest, __constant uint *target) {
#define LIMB(k)                                         \
    if (BSWAP32(digest.s##k) != target[k]) {            \
        return BSWAP32(digest.s##k) < target[k];        \
    }
    LIMB(7) LIMB(6) LIMB(5) LIMB(4) LIMB(3) LIMB(2) LIMB(1) LIMB(0)
#undef LIMB
    return true; /* equal to the target, which still meets it */
}

/* job holds the midstate (words 0-7), the header's three words before the nonce (8-10),
   and the target as 32-bit little-endian limbs, least significant first (11-18).
   Work item i tries nonce base + i. The lowest i whose hash meets the target goes to
   *best, which the host sets to 0xffffffff beforehand. */
__kernel void search_nonces(__constant uint *job, uint base, uint count, __global uint *best) {
    uint i = get_global_id(0);
    if (i >= count) {
        return;
    }

    /* The header's second 64-byte block: its last 16 bytes, then padding for an 80-byte
       message. The header stores the nonce little-endian; SHA-256 reads big-endian words. */
    uint16 block1 = (uint16)(job[8], job[9], job[10], BSWAP32(base + i), 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640);
    uint8 first = compress(vload8(0, job), block1);

    /* The second SHA-256 hashes the 32-byte first digest. */
    uint8 iv = (uint8)(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
    uint8 digest = compress(iv, (uint16)(first, 0x80000000, 0, 0, 0, 0, 0, 0, 256));

    if (meets_target(digest, job + 11)) {
        atomic_min(best, i);
    }
}
