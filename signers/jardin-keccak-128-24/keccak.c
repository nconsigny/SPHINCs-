/*
 * Minimal Keccak-256 (Ethereum-flavour, 0x01 padding).  Public domain.
 *
 * Derived from the Keccak team's reference pseudocode — compact single-block
 * absorb + squeeze tuned for ≤ 1 MB messages and a fixed 32-byte output.
 * All inputs we hash are ≤ 8 KB, so the streaming API is omitted.
 */

#include <string.h>
#include "keccak.h"

#define RATE_BYTES 136   /* 1600 - 2*256 = 1088 bits = 136 bytes */
#define ROUNDS     24

static const uint64_t RC[ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44,
};

static const unsigned PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,
     8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1,
};

static inline uint64_t rol64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t s[25]) {
    uint64_t C[5], D[5], B[25];
    for (int r = 0; r < ROUNDS; r++) {
        /* Theta */
        for (int x = 0; x < 5; x++)
            C[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x+4)%5] ^ rol64(C[(x+1)%5], 1);
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                s[y+x] ^= D[x];
        /* Rho + Pi */
        uint64_t t = s[1];
        for (int i = 0; i < 24; i++) {
            unsigned j = PI[i];
            uint64_t tmp = s[j];
            s[j] = rol64(t, RHO[i]);
            t = tmp;
        }
        /* Chi */
        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++) B[x] = s[y+x];
            for (int x = 0; x < 5; x++)
                s[y+x] = B[x] ^ (~B[(x+1)%5] & B[(x+2)%5]);
        }
        /* Iota */
        s[0] ^= RC[r];
    }
}

static inline uint64_t load64(const uint8_t *x) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)x[i] << (8*i);
    return v;
}

static inline void store64(uint8_t *x, uint64_t v) {
    for (int i = 0; i < 8; i++) x[i] = (uint8_t)(v >> (8*i));
}

void keccak256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    uint64_t s[25] = {0};

    /* Absorb full blocks. */
    while (inlen >= RATE_BYTES) {
        for (int i = 0; i < RATE_BYTES / 8; i++)
            s[i] ^= load64(in + 8*i);
        keccak_f1600(s);
        in    += RATE_BYTES;
        inlen -= RATE_BYTES;
    }

    /* Absorb final partial block with 0x01 padding (legacy Keccak). */
    uint8_t last[RATE_BYTES] = {0};
    memcpy(last, in, inlen);
    last[inlen]       ^= 0x01;
    last[RATE_BYTES-1] ^= 0x80;
    for (int i = 0; i < RATE_BYTES / 8; i++)
        s[i] ^= load64(last + 8*i);
    keccak_f1600(s);

    /* Squeeze 32 bytes. */
    for (int i = 0; i < 4; i++) store64(out + 8*i, s[i]);
}
