/*
 * JARDIN address setter functions — write full 4-byte big-endian integers
 * into the 32-byte ADRS, matching the layout in
 *   src/SLH-DSA-keccak-128-24verifier.sol
 *   script/jardin_primitives.py
 *
 * Each uint32 field occupies its own 4-byte slot; there is no compression
 * to single bytes as in the SHA-2 variant's ADRSc.
 */
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "utils.h"

void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_LAYER], layer);
}

void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
    ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8, tree);
}

void set_type(uint32_t addr[8], uint32_t type)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TYPE], type);
}

/*
 * Copy the layer and tree fields.  In the JARDIN layout that's bytes 0..11
 * (4 for layer + 8 for tree).
 */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
}

void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_KP_ADDR], keypair);
}

/*
 * Copy layer + tree + keypair (i.e. bytes 0..19 in the JARDIN layout).
 */
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
    memcpy((unsigned char *)out + SPX_OFFSET_KP_ADDR,
           (unsigned char *)in  + SPX_OFFSET_KP_ADDR, 4);
}

void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR], chain);
}

/*
 * hash_addr and tree_height share the 4-byte slot at SPX_OFFSET_HASH_ADDR
 * (= SPX_OFFSET_TREE_HGT = 24).  The type of the ADRS determines the
 * semantic.
 */
void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR], hash);
}

void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_HGT], tree_height);
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}
