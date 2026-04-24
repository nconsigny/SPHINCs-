/*
 * JARDIN-Keccak-128-24 parameters — JARDIN-family twin of SP 800-230
 * SLH-DSA-*-128-24 (same dimensions, keccak256 hash primitive, 32-byte
 * ADRS, LSB-first digest parsing within the 256-bit keccak output).
 *
 *   n=16  h=22  d=1  h'=22  a=24  k=6  w=4  lgw=2  m=21
 *
 * On-wire signature size: 3,856 bytes (matches the SHA-2 variant).
 * Pairs with src/SLH-DSA-keccak-128-24verifier.sol.
 */
#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H
#define SPX_NAMESPACE(s) SPX_KECCAK_##s
#define SPX_N 16
#define SPX_FULL_HEIGHT 22
#define SPX_D 1
#define SPX_FORS_HEIGHT 24
#define SPX_FORS_TREES 6
#define SPX_WOTS_W 4
#define SPX_ADDR_BYTES 32
#if SPX_WOTS_W != 4
  #error this fork is w=4 only
#endif
#define SPX_WOTS_LOGW 2
#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)    /* 64 */
#define SPX_WOTS_LEN2 4                              /* ceil(log_4(64*3))+1 = 4 */
#define SPX_WOTS_LEN   (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)
#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
    #error SPX_D should always divide SPX_FULL_HEIGHT
#endif
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + \
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)
#include "jardin_offsets.h"
#endif
