/*
 * JARDIN-Keccak-128-24 one-shot CLI.
 *
 *   Usage:  jardin-keccak-128-24 <seed_48B_hex> <message_hex> <optrand_16B_hex>
 *
 * `seed_48B` = sk_seed(16) || sk_prf(16) || pk_seed(16) — pass whatever
 * derivation you like from the outside.  `optrand_16B` selects the per-sig
 * randomizer (NIST allows any value, including all-zero for determinism).
 *
 * Output to stdout (one line, hex, no 0x):
 *   pk_seed(16) || pk_root(16) || sig(SPX_BYTES = 3856)
 *
 *   = 32 + 3856 = 3888 bytes = 7776 hex chars.
 *
 * Exit status 0 on success, non-zero on usage or internal error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "api.h"
#include "randombytes.h"

/* set_rng_buffer is declared here (not in randombytes.h) because it's an
   internal hook for this harness only, not part of the SPHINCS+ API. */
extern void set_rng_buffer(const unsigned char *buf, unsigned long long len);

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, unsigned char *out, size_t out_len)
{
    size_t hlen = strlen(hex);
    if (hlen >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        hlen -= 2;
    }
    if (hlen != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static void hex_print(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr,
            "Usage: %s <seed_48B_hex> <message_hex> <optrand_16B_hex>\n"
            "  seed = sk_seed(16) || sk_prf(16) || pk_seed(16)\n"
            "  message = arbitrary-length hex (pad nothing)\n"
            "  optrand = %d bytes (the per-sig randomizer)\n"
            "\nOutput: hex(pk_seed(16) || pk_root(16) || sig(%d))\n",
            argv[0], SPX_N, SPX_BYTES);
        return 2;
    }

    unsigned char seed[CRYPTO_SEEDBYTES];        /* = 3 * SPX_N = 48 */
    if (hex_decode(argv[1], seed, sizeof(seed)) != 0) {
        fprintf(stderr, "bad seed hex (need %zu bytes)\n", sizeof(seed));
        return 1;
    }

    size_t msg_hex_len = strlen(argv[2]);
    if (msg_hex_len >= 2 && argv[2][0] == '0' &&
        (argv[2][1] == 'x' || argv[2][1] == 'X')) msg_hex_len -= 2;
    if (msg_hex_len & 1) {
        fprintf(stderr, "message hex must have even length\n");
        return 1;
    }
    size_t msg_len = msg_hex_len / 2;
    if (msg_len != 32) {
        fprintf(stderr, "message must be exactly 32 bytes (64 hex chars); the on-chain "
                        "convention is bytes32. got %zu bytes\n", msg_len);
        return 1;
    }
    unsigned char *msg = (unsigned char *)malloc(msg_len);
    if (!msg) { fprintf(stderr, "oom\n"); return 1; }
    if (hex_decode(argv[2], msg, msg_len) != 0) {
        fprintf(stderr, "bad message hex\n"); free(msg); return 1;
    }

    unsigned char optrand[SPX_N];
    if (hex_decode(argv[3], optrand, sizeof(optrand)) != 0) {
        fprintf(stderr, "bad optrand hex (need %d bytes)\n", SPX_N);
        free(msg); return 1;
    }

    unsigned char pk[SPX_PK_BYTES];              /* = 32 */
    unsigned char sk[SPX_SK_BYTES];              /* = 64 */
    fprintf(stderr, "  keygen (single XMSS, 2^%d leaves)...\n", SPX_FULL_HEIGHT);
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "keygen failed\n"); free(msg); return 1;
    }
    fprintf(stderr, "  pk_seed = "); for (int i = 0; i < 4; i++) fprintf(stderr, "%02x", pk[i]); fprintf(stderr, "...\n");
    fprintf(stderr, "  pk_root = "); for (int i = 0; i < 4; i++) fprintf(stderr, "%02x", pk[SPX_N + i]); fprintf(stderr, "...\n");

    unsigned char sig[SPX_BYTES];                /* = 3856 */
    size_t siglen = 0;
    set_rng_buffer(optrand, sizeof(optrand));
    fprintf(stderr, "  signing (FORS + XMSS)...\n");
    if (crypto_sign_signature(sig, &siglen, msg, msg_len, sk) != 0) {
        fprintf(stderr, "sign failed\n"); free(msg); return 1;
    }
    if (siglen != SPX_BYTES) {
        fprintf(stderr, "unexpected siglen %zu != %d\n", siglen, SPX_BYTES);
        free(msg); return 1;
    }
    fprintf(stderr, "  sig: %zu bytes\n", siglen);

    /* Emit pk_seed || pk_root || sig as hex. */
    unsigned char out[2 * SPX_N + SPX_BYTES];
    memcpy(out,              pk,           SPX_N);            /* pk_seed */
    memcpy(out + SPX_N,      pk + SPX_N,   SPX_N);            /* pk_root */
    memcpy(out + 2 * SPX_N,  sig,          SPX_BYTES);
    hex_print(out, sizeof(out));

    free(msg);
    return 0;
}
