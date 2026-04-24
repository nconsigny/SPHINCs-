/*
 * Tweakable hash for JARDIN-Keccak-128-24.
 *
 *   thash(out, in[0..inblocks-1], ctx, ADRS) :=
 *       keccak256(pub_seed32 ‖ ADRS32 ‖ in[0]_pad32 ‖ in[1]_pad32 ‖ ...)[0..15]
 *
 * Each 16-byte input block is zero-padded to 32 bytes (value in the top 16,
 * zeros in the bottom 16).  This matches the Solidity verifier's memory
 * layout (each value is stored as `bytes32` with top 16 = value).
 *
 * For n=16 the three shapes used by the algorithm are:
 *   F   (inblocks=1) : 96-byte  input    — seed ‖ adrs ‖ x
 *   H   (inblocks=2) : 128-byte input    — seed ‖ adrs ‖ L ‖ R
 *   T_l (inblocks=k) : 64+32k-byte input — seed ‖ adrs ‖ roots / chain-tops
 *
 * The largest call we make is T_l over WOTS_LEN=68 blocks → 2240 bytes.
 */

#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "thash.h"
#include "keccak.h"

#define MAX_INBLOCKS SPX_WOTS_LEN   /* biggest caller is T_l(WOTS) with 68 blocks */

void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[32 + SPX_ADDR_BYTES + 32 * MAX_INBLOCKS];
    unsigned char digest[32];

    /* seed32: pub_seed (16 B) zero-padded to 32. */
    memcpy(buf, ctx->pub_seed, SPX_N);
    memset(buf + SPX_N, 0, 32 - SPX_N);

    /* 32-byte JARDIN ADRS. */
    memcpy(buf + 32, addr, SPX_ADDR_BYTES);

    /* Each in[i] is SPX_N=16 bytes; pad to 32 B in place. */
    for (unsigned i = 0; i < inblocks; i++) {
        memcpy(buf + 32 + SPX_ADDR_BYTES + 32 * i, in + i * SPX_N, SPX_N);
        memset(buf + 32 + SPX_ADDR_BYTES + 32 * i + SPX_N, 0, 32 - SPX_N);
    }

    size_t len = 32 + SPX_ADDR_BYTES + 32 * (size_t)inblocks;
    keccak256(digest, buf, len);
    memcpy(out, digest, SPX_N);
}
