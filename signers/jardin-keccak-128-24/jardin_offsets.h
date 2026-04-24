/*
 * JARDIN 32-byte ADRS layout (matches src/SLH-DSA-keccak-128-24verifier.sol
 * and script/jardin_primitives.py).
 *
 *   bytes  0.. 3   layer           uint32 BE
 *   bytes  4..11   tree            uint64 BE
 *   bytes 12..15   type            uint32 BE
 *   bytes 16..19   kp  (keypair)   uint32 BE
 *   bytes 20..23   ci  (chain)     uint32 BE   (0 for FORS/TREE)
 *   bytes 24..27   cp  (chain pos / tree_height)     uint32 BE
 *   bytes 28..31   ha  (hash addr / tree_index)      uint32 BE
 *
 * Every field is a full 4-byte (or 8-byte) big-endian integer.  Unlike the
 * compressed SHA-2 ADRSc, there are no one-byte fields here.
 */
#ifndef JARDIN_OFFSETS_H_
#define JARDIN_OFFSETS_H_

#define SPX_OFFSET_LAYER       0   /* 4-byte field */
#define SPX_OFFSET_TREE        4   /* 8-byte field */
#define SPX_OFFSET_TYPE       12   /* 4-byte field */
#define SPX_OFFSET_KP_ADDR    16   /* 4-byte field */
#define SPX_OFFSET_CHAIN_ADDR 20   /* 4-byte field */
#define SPX_OFFSET_TREE_HGT   24   /* 4-byte field — shared slot for cp */
#define SPX_OFFSET_HASH_ADDR  24   /* 4-byte field — same slot (hash_address == cp for WOTS) */
#define SPX_OFFSET_TREE_INDEX 28   /* 4-byte field — shared slot for ha */

#define SPX_JARDIN 1
#define SPX_N_KECCAK 16

#endif
