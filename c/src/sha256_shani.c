/* SHA-256 compression with the x86 SHA extensions ("SHA-NI"; Intel since Goldmont and
   Ice Lake, AMD since Zen). One sha256rnds2 instruction performs two rounds.

   The functions that use them carry a target attribute, so the build needs no -msha
   and the binary still runs on CPUs without them: sha256_compress only calls in here
   after sha256_shani_supported says yes. */

#include "sha256.h"

#ifdef SHA256_HAVE_SHANI

#include <cpuid.h>
#include <immintrin.h>

#define SHANI __attribute__((target("sha,sse4.1")))

bool sha256_shani_supported(void) {
    unsigned eax, ebx, ecx, edx;
    /* SSSE3 and SSE4.1 for the shuffles, then the SHA extensions themselves. */
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & bit_SSSE3) || !(ecx & bit_SSE4_1)) {
        return false;
    }
    return __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) && (ebx & bit_SHA);
}

/* Rounds i to i+3, using message words w. The state lives in two vectors, ABEF and
   CDGH. sha256rnds2 takes both, returns the new ABEF, and the old ABEF becomes the new
   CDGH, so the two variables swap roles after the first call and swap back after the second. */
SHANI static inline void four_rounds(__m128i *abef, __m128i *cdgh, __m128i w, int i) {
    __m128i wk = _mm_add_epi32(w, _mm_loadu_si128((const __m128i *)&SHA256_K[i]));
    *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, wk);
    *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, _mm_shuffle_epi32(wk, 0x0E));
}

/* The next four message words, from the 16 before them in four vectors, oldest first:
   W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]. sha256msg1 adds the σ0 terms,
   alignr supplies W[t-7..t-4], and sha256msg2 adds the σ1 terms. */
SHANI static inline __m128i next_words(__m128i w0, __m128i w1, __m128i w2, __m128i w3) {
    __m128i sum = _mm_add_epi32(_mm_sha256msg1_epu32(w0, w1), _mm_alignr_epi8(w3, w2, 4));
    return _mm_sha256msg2_epu32(sum, w3);
}

SHANI void sha256_compress_shani(uint32_t state[8], const uint32_t block[16]) {
    /* Rearrange A..H into ABEF and CDGH. Vector names list lanes from highest to lowest. */
    __m128i dcba = _mm_loadu_si128((const __m128i *)&state[0]);
    __m128i hgfe = _mm_loadu_si128((const __m128i *)&state[4]);
    __m128i cdab = _mm_shuffle_epi32(dcba, 0xB1);
    __m128i efgh = _mm_shuffle_epi32(hgfe, 0x1B);
    __m128i abef = _mm_alignr_epi8(cdab, efgh, 8);
    __m128i cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);
    const __m128i abef_in = abef, cdgh_in = cdgh;

    /* Byte-oriented implementations byte-swap each word here; ours are already integers. */
    __m128i w0 = _mm_loadu_si128((const __m128i *)&block[0]);
    __m128i w1 = _mm_loadu_si128((const __m128i *)&block[4]);
    __m128i w2 = _mm_loadu_si128((const __m128i *)&block[8]);
    __m128i w3 = _mm_loadu_si128((const __m128i *)&block[12]);
    for (int i = 0; i < 64; i += 16) {
        four_rounds(&abef, &cdgh, w0, i);
        four_rounds(&abef, &cdgh, w1, i + 4);
        four_rounds(&abef, &cdgh, w2, i + 8);
        four_rounds(&abef, &cdgh, w3, i + 12);
        if (i < 48) {
            w0 = next_words(w0, w1, w2, w3);
            w1 = next_words(w1, w2, w3, w0);
            w2 = next_words(w2, w3, w0, w1);
            w3 = next_words(w3, w0, w1, w2);
        }
    }
    abef = _mm_add_epi32(abef, abef_in);
    cdgh = _mm_add_epi32(cdgh, cdgh_in);

    /* And back to A..H. */
    __m128i feba = _mm_shuffle_epi32(abef, 0x1B);
    __m128i dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    _mm_storeu_si128((__m128i *)&state[0], _mm_blend_epi16(feba, dchg, 0xF0));
    _mm_storeu_si128((__m128i *)&state[4], _mm_alignr_epi8(dchg, feba, 8));
}

#endif
