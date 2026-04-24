/*
 * Hash primitives for JARDIN-Keccak-128-24.
 *
 *   PRF(pub_seed, sk_seed, ADRS)      = keccak(pub_seed32 ‖ ADRS32 ‖ sk_seed32)[0..15]
 *   PRFmsg(sk_prf, opt_rand, M)       = keccak(sk_prf32 ‖ opt_rand32 ‖ M)[0..15]
 *   Hmsg(R, pub_seed, pub_root, M)    = keccak(pub_seed32 ‖ pub_root32 ‖ R32 ‖ M32 ‖ 0xFF..FB)[0..m-1]
 *
 * All 16-byte (SPX_N) values are zero-padded to 32 bytes in the hash input
 * (value in the top 16 B, zero in the bottom 16 B) — matches the on-chain
 * verifier's convention.  This zero-padding is the reason the hash input
 * shape differs from the FIPS 205 SHA-2 form.
 *
 * Hmsg uses a one-shot keccak (no MGF1, no HMAC), fixed 160-byte input.
 * Digest is the full 256-bit keccak output; we return its 32 bytes and let
 * hash_message() parse them LSB-first-within-256-bit-integer per the JARDIN
 * convention.
 */

#include <stdint.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "keccak.h"
#include "params.h"

/*
 * For JARDIN Keccak, initialize_hash_function has nothing to do.
 * The ctx struct (see context.h) only holds pub_seed/sk_seed — there is
 * no precomputed SHA-256 state to seed.
 */
void initialize_hash_function(spx_ctx *ctx) { (void)ctx; }

/*
 * Zero-pad a 16-byte value to 32 bytes (value in first 16, zero in the rest).
 */
static inline void pad32(unsigned char out[32], const unsigned char v[SPX_N])
{
    memcpy(out, v, SPX_N);
    memset(out + SPX_N, 0, 32 - SPX_N);
}

void prf_addr(unsigned char *out, const spx_ctx *ctx, const uint32_t addr[8])
{
    unsigned char buf[32 + SPX_ADDR_BYTES + 32];   /* 32 + 32 + 32 = 96 B */
    unsigned char digest[32];

    pad32(buf,               ctx->pub_seed);
    memcpy(buf + 32, addr, SPX_ADDR_BYTES);        /* 32-byte JARDIN ADRS */
    pad32(buf + 32 + SPX_ADDR_BYTES, ctx->sk_seed);

    keccak256(digest, buf, sizeof(buf));
    memcpy(out, digest, SPX_N);
}

/*
 * PRFmsg(sk_prf, opt_rand, M):
 *   keccak(sk_prf32 ‖ opt_rand32 ‖ M)[0..n-1]
 *
 * The reference gen_message_random has a weird dual-path structure for
 * large messages that keeps its SHA buffer bounded; for us M is always
 * 32 B (a bytes32 message from the on-chain caller), so a single static
 * buffer is fine.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    /* Buffer size: pad32(sk_prf) + pad32(optrand) + M.  M is typically 32 B
       but we allow up to 8 KB for the odd caller. */
    unsigned char buf[32 + 32 + 8192];
    unsigned char digest[32];

    if (mlen > sizeof(buf) - 64) {
        /* Unsupported in this fork; our harness only signs 32-byte messages. */
        memset(R, 0, SPX_N);
        return;
    }

    pad32(buf,      sk_prf);
    pad32(buf + 32, optrand);
    memcpy(buf + 64, m, (size_t)mlen);

    keccak256(digest, buf, (size_t)(64 + mlen));
    memcpy(R, digest, SPX_N);
}

/*
 * Hmsg(R, pub_seed, pub_root, M) with the JARDIN domain separator:
 *   keccak(pub_seed32 ‖ pub_root32 ‖ R32 ‖ M32 ‖ 0xFF..FB)[full 32 B]
 *
 * Output the 32-byte keccak result; digest_to_indices() (below) does the
 * LSB-first-within-256-bit-integer parsing into md[0..k-1] + leaf_idx.
 *
 * Domain = FULL - 4 = 0xFF..FB (matches the Solidity verifier and Python
 * signer).  No MGF1 — a single keccak call suffices since we want the full
 * 32-byte output regardless of m.
 */

#define SPX_HMSG_DOMAIN_LOW  ((uint64_t)0xFFFFFFFFFFFFFFFBULL)
#define SPX_HMSG_DOMAIN_HIGH ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

static void hmsg_keccak(unsigned char digest[32],
                        const unsigned char *R,
                        const unsigned char *pk,
                        const unsigned char *m, unsigned long long mlen)
{
    unsigned char buf[32 + 32 + 32 + 32 + 32];   /* 5 × 32 B = 160 B */
    /*
     * Layout (matches Solidity mstore order):
     *   buf[  0.. 31] = pk_seed || zero_pad       (pk[0..SPX_N-1] || zeros)
     *   buf[ 32.. 63] = pk_root || zero_pad       (pk[SPX_N..2N-1] || zeros)
     *   buf[ 64.. 95] = R || zero_pad
     *   buf[ 96..127] = M (must be 32 B for the on-chain convention)
     *   buf[128..159] = 0xFF..FB (32-B BE)
     */
    if (mlen != 32) {
        /* Unsupported — our on-chain verifier always hashes a bytes32 M. */
        memset(digest, 0, 32);
        return;
    }

    pad32(buf,       pk);                 /* pk_seed (first SPX_N bytes of pk) */
    pad32(buf + 32,  pk + SPX_N);         /* pk_root */
    pad32(buf + 64,  R);
    memcpy(buf + 96, m, 32);
    /* Domain 0xFF..FB as 32-byte BE */
    for (int i = 0; i < 32; i++) buf[128 + i] = 0xFF;
    buf[128 + 31] = 0xFB;

    keccak256(digest, buf, sizeof(buf));
}

/*
 * digest_to_indices (JARDIN Keccak convention):
 *   Treat the 32-byte keccak output as one 256-bit BIG-ENDIAN integer I.
 *   md[t]   = (I >> (a·t))      & (2^a - 1)   for t = 0..k-1
 *   leaf_idx = (I >> (k·a))     & (2^h - 1)
 *
 * Practical extraction: big-endian load of the 32 bytes, then bit-shifts.
 * Because a·k = 144 ≤ 168 (m·8) and leaf takes 22 more bits (total 166),
 * we always stay within the 256-bit digest.
 */
static inline uint64_t be_load64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void digest_to_indices(const unsigned char digest[32],
                              uint32_t *indices, uint64_t *tree,
                              uint32_t *leaf_idx)
{
    /* Split I into two halves for 128-bit arithmetic without a full bignum. */
    uint64_t hi = be_load64(digest + 0)  ^ 0;   /* bits 192..255 */
    uint64_t mh = be_load64(digest + 8)  ^ 0;   /* bits 128..191 */
    uint64_t ml = be_load64(digest + 16) ^ 0;   /* bits  64..127 */
    uint64_t lo = be_load64(digest + 24) ^ 0;   /* bits   0.. 63 */
    (void)hi;   /* the top 64 bits are above the bits we consume */

    /*
     * md[t] = (I >> (a·t)) & ((1<<a)-1), where I is the 256-bit big-endian
     * integer built from the digest bytes.  Below, `lo`..`hi` are 64-bit
     * slices of I with `lo` holding bits 0..63, `hi` holding bits 192..255.
     *
     * We support the general case (a not necessarily byte-aligned, but
     * a < 32 so a single 32-bit result is enough) with a 128-bit spillover
     * from the adjacent slice.
     */
    const uint64_t A_MASK = ((uint64_t)1 << SPX_FORS_HEIGHT) - 1;
    for (int t = 0; t < SPX_FORS_TREES; t++) {
        unsigned n = (unsigned)SPX_FORS_HEIGHT * (unsigned)t;
        unsigned word = n >> 6;
        unsigned bit  = n & 63;
        uint64_t w0, w1;
        switch (word) {
            case 0: w0 = lo;  w1 = ml; break;
            case 1: w0 = ml;  w1 = mh; break;
            case 2: w0 = mh;  w1 = hi; break;
            default: w0 = 0;  w1 = 0;  break;
        }
        uint64_t v = (w0 >> bit);
        if (bit + SPX_FORS_HEIGHT > 64) v |= w1 << (64 - bit);
        indices[t] = (uint32_t)(v & A_MASK);
    }

    /* leaf_idx = (I >> (k·a)) & (2^h - 1).  For k=6, a=24, h=22: bits 144..165. */
    unsigned n    = SPX_FORS_TREES * SPX_FORS_HEIGHT;   /* 144 */
    unsigned word = n >> 6;                              /* 2 (so `mh`) */
    unsigned bit  = n & 63;                              /* 16 */
    uint64_t w0, w1;
    switch (word) {
        case 0: w0 = lo; w1 = ml; break;
        case 1: w0 = ml; w1 = mh; break;
        case 2: w0 = mh; w1 = hi; break;
        default: w0 = 0; w1 = 0; break;
    }
    uint64_t v = (w0 >> bit);
    if (bit + SPX_FULL_HEIGHT > 64) v |= w1 << (64 - bit);
    *leaf_idx = (uint32_t)(v & (((uint64_t)1 << SPX_FULL_HEIGHT) - 1));

    /* d = 1: no tree_idx bits in the digest. */
    *tree = 0;
}

/*
 * Matches the reference's hash_message signature.
 *    digest : SPX_FORS_MSG_BYTES bytes consumed by the FORS layer (we
 *             pack indices[] back as LSB-first bit-pairs so
 *             message_to_indices() in fors.c produces the same md[] we
 *             computed above).
 *    tree, leaf_idx : as parsed directly from the 256-bit digest.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
    unsigned char kdigest[32];
    hmsg_keccak(kdigest, R, pk, m, mlen);

    uint32_t indices[SPX_FORS_TREES];
    digest_to_indices(kdigest, indices, tree, leaf_idx);

    /*
     * Re-pack indices[] into `digest` LSB-first so that fors.c's stock
     * message_to_indices (which reads bit n from `m[n>>3] bit (n&7)`)
     * reproduces the same indices[].  General bit-level write handles
     * non-byte-aligned a too (e.g. dev params with a=4).
     */
    memset(digest, 0, SPX_FORS_MSG_BYTES);
    unsigned bit_offset = 0;
    for (int t = 0; t < SPX_FORS_TREES; t++) {
        uint32_t v = indices[t];
        for (int j = 0; j < SPX_FORS_HEIGHT; j++) {
            unsigned bit = (v >> j) & 1u;
            digest[bit_offset >> 3] |= (unsigned char)(bit << (bit_offset & 7));
            bit_offset++;
        }
    }
}
