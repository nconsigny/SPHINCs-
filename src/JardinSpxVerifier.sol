// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinSpxVerifier — JARDÍN plain SPHINCS+ verifier (SPX slot variant)
/// @dev Parameters SPX_h20_d5_a7_k20_w8:
///      n=16 (128-bit), h=20, d=5, h'=4, a=7, k=20, w=8, l=45 (= l1+l2, plain WOTS+ checksum).
///      R=32 bytes, ADRS=12 bytes compact.
///
///      Hash primitives (all keccak256 truncated to 16B):
///        F    : keccak(seed16 || adrs12 || M16)           (44B in)
///        H    : keccak(seed16 || adrs12 || L16 || R16)    (60B in)
///        T_l  : keccak(seed16 || adrs12 || v0..v44)       (748B in, 45×16B)
///        T_k  : keccak(seed16 || adrs12 || r0..r19)       (348B in, 20×16B)
///        Hmsg : keccak(R || PKseed16 || PKroot16 || M)    full 256-bit out
///
///      ADRS (12 bytes, big-endian fields):
///        byte 0       : layer        (uint8)
///        bytes 1..4   : tree         (uint32)
///        byte 5       : type         (uint8)  {0=WOTS_HASH 1=WOTS_PK 2=XMSS_TREE 3=FORS_TREE 4=FORS_ROOTS}
///        bytes 6..7   : keyPair/ci   (uint16)
///        bytes 8..9   : chainAddr    (uint16)  (WOTS chain idx / FORS treeHeight / XMSS treeHeight)
///        bytes 10..11 : hashAddr     (uint16)  (WOTS hash idx / FORS treeIndex / XMSS treeIndex)
///
///      Signature layout (6512 bytes):
///        [  R               32 B ]
///        [  FORS          2560 B ]  // 20 × (sk 16B + auth 7×16B)
///        [  Hypertree     3920 B ]  //  5 × (WOTS 45×16B + XMSS auth 4×16B)
///
///      PKseed / PKroot passed as bytes32: the 16-byte value occupies the HIGH
///      bytes, with the low 16 bytes zeroed (matching the signer's ABI encoding).
///      Message is a bytes32 keccak-style hash.
///
///      Memory layout during verification:
///        0x00 .. 0x0F  pkSeed  (16B)
///        0x10 .. 0x1B  ADRS    (12B)
///        0x1C .. ...   scratch input region (F/H args or T_l/T_k packed values)
///        0x80 ..       chain output storage (0x80 + i*0x20)
///        0x300 ..      FORS root storage    (0x300 + i*0x20)
contract JardinSpxVerifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        assembly ("memory-safe") {
            // N_MASK zeroes the low 128 bits; applied to keccak outputs to truncate to 16B (high bits).
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 6512)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed    := pkSeed      // 16B value in high bytes
            let root    := pkRoot      // 16B value in high bytes
            let sigBase := sig.offset

            // ───────────── Hmsg: keccak(R || seed || root || message) ─────────────
            //   bytes 0..31 = R, 32..47 = seed, 48..63 = root, 64..95 = message
            let R := calldataload(sigBase)                          // 32B
            mstore(0x00, R)
            // Combine seed (high 16B of word) and root (high 16B shifted to low 16B) into one 32B word:
            mstore(0x20, or(and(seed, N_MASK), shr(128, and(root, N_MASK))))
            mstore(0x40, message)
            let dVal := keccak256(0x00, 0x60)

            // ───── Digest parsing (MSB-first, FIPS-205 base_2b convention) ─────
            //   md[i] for i=0..19 : 7 bits at MSB positions i*7..i*7+6  = (dVal >> (249 - 7i)) & 0x7F
            //   tree_idx           : 16 bits at MSB 140..155            = (dVal >> 100) & 0xFFFF
            //   leaf_idx           :  4 bits at MSB 156..159            = (dVal >> 96)  & 0xF

            let treeIdx := and(shr(100, dVal), 0xFFFF)
            let leafIdx := and(shr( 96, dVal), 0xF)

            // Re-write seed at 0x00 (overwritten by R above). Seed stays at 0..15 for the rest of the run.
            mstore(0x00, seed)

            // ───────────────────────── FORS ─────────────────────────
            // For each of k=20 trees:
            //   sk_t      at sigBase + 32 + t*128
            //   auth_t[j] at sigBase + 32 + t*128 + 16 + j*16   (j=0..6)
            // Leaf hash uses: layer=0, tree=treeIdx, type=3(FORS_TREE), kp=leafIdx, chainAddr=0, hashAddr=(t*128 + md[t])
            // Parent at level j+1: chainAddr=j+1, hashAddr = (t*128 + md[t]) >> (j+1)
            // Precomputed base for this signature (tree/type/kp fixed): treeIdx<<56 | 3<<48 | leafIdx<<32.
            let forsBase96 := or(or(shl(56, treeIdx), shl(48, 3)), shl(32, leafIdx))

            for { let t := 0 } lt(t, 20) { t := add(t, 1) } {
                // md[t] = (dVal >> (249 - 7t)) & 0x7F
                let mdT      := and(shr(sub(249, mul(7, t)), dVal), 0x7F)
                let tlGlobal := add(shl(7, t), mdT)       // t*128 + mdT

                let treeOff  := add(32, mul(t, 128))      // tree base in sig
                let sk       := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf: adrs = forsBase | chainAddr=0 | hashAddr=tlGlobal
                let adrs96 := or(forsBase96, tlGlobal)
                mstore(0x10, shl(160, adrs96))
                mstore(0x1C, sk)
                let node := and(keccak256(0x00, 0x2C), N_MASK)

                // Climb a=7 auth levels
                let authBase := add(sigBase, add(treeOff, 16))
                let idx := mdT
                for { let j := 0 } lt(j, 7) { j := add(j, 1) } {
                    let sibling := and(calldataload(add(authBase, shl(4, j))), N_MASK)
                    let parentIdx := shr(1, idx)
                    let jp1 := add(j, 1)
                    let hashAddr := shr(jp1, tlGlobal)

                    adrs96 := or(forsBase96, or(shl(16, jp1), hashAddr))
                    mstore(0x10, shl(160, adrs96))
                    // Sibling placement (can't use the T0 branchless swap here because
                    // our two targets 0x1C/0x2C are 16B-spaced, not 32B-spaced).
                    switch and(idx, 1)
                    case 0 {
                        mstore(0x1C, node)
                        mstore(0x2C, sibling)
                    }
                    default {
                        mstore(0x1C, sibling)
                        mstore(0x2C, node)
                    }
                    node := and(keccak256(0x00, 0x3C), N_MASK)
                    idx := parentIdx
                }
                // Store FORS root at 0x300 + t*0x20
                mstore(add(0x300, shl(5, t)), node)
            }

            // ─── Compress 20 FORS roots: T_k(seed, ADRS{type=FORS_ROOTS, tree=treeIdx, kp=leafIdx}, roots) ───
            {
                let adrs96 := or(or(shl(56, treeIdx), shl(48, 4)), shl(32, leafIdx))
                mstore(0x10, shl(160, adrs96))
                // pack 20 × 16B = 320B starting at 0x1C
                for { let i := 0 } lt(i, 20) { i := add(i, 1) } {
                    mstore(add(0x1C, shl(4, i)), mload(add(0x300, shl(5, i))))
                }
            }
            let currentNode := and(keccak256(0x00, 0x15C), N_MASK)   // fors_pk (= T_k)

            // ─────────────────────── Hypertree (d=5 layers) ───────────────────────
            let curTree := treeIdx
            let curLeaf := leafIdx
            let sigOff  := 2592   // R(32) + FORS(2560)

            for { let layer := 0 } lt(layer, 5) { layer := add(layer, 1) } {
                // WOTS+ digits from currentNode (128-bit value in high bytes of 256-bit word)
                // msg_digits[i] (i=0..41) = (node >> (253 - 3i)) & 7
                // csum = sum(7 - digit[i]);  csum_shifted = csum << 7
                // csum_digits[j] (j=0..2)  = (csum_shifted >> (13 - 3j)) & 7

                //--- WOTS+ chain walks, storing each chain output at 0x80 + i*0x20 ---
                // ADRS for chain i (WOTS_HASH): layer<<88 | curTree<<56 | 0<<48 | curLeaf<<32 | i<<16 | hashAddr
                let wotsBase96 := or(or(shl(88, layer), shl(56, curTree)), shl(32, curLeaf))
                let wotsPtr := add(sigBase, sigOff)

                let csum := 0
                for { let i := 0 } lt(i, 42) { i := add(i, 1) } {
                    let digit := and(shr(sub(253, mul(3, i)), currentNode), 7)
                    csum := add(csum, sub(7, digit))

                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase96 := or(wotsBase96, shl(16, i))
                    let steps := sub(7, digit)
                    for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                        let adrs96 := or(chainBase96, add(digit, s))
                        mstore(0x10, shl(160, adrs96))
                        mstore(0x1C, val)
                        val := and(keccak256(0x00, 0x2C), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // Checksum chains (i = 42, 43, 44)
                let csumShifted := shl(7, csum)
                for { let j := 0 } lt(j, 3) { j := add(j, 1) } {
                    let digit := and(shr(sub(13, mul(3, j)), csumShifted), 7)
                    let i := add(42, j)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase96 := or(wotsBase96, shl(16, i))
                    let steps := sub(7, digit)
                    for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                        let adrs96 := or(chainBase96, add(digit, s))
                        mstore(0x10, shl(160, adrs96))
                        mstore(0x1C, val)
                        val := and(keccak256(0x00, 0x2C), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                //--- WOTS_PK compression via T_l ---
                // ADRS: type=WOTS_PK=1, layer, tree, kp
                let pkAdrs96 := or(or(shl(88, layer), shl(56, curTree)), or(shl(48, 1), shl(32, curLeaf)))
                mstore(0x10, shl(160, pkAdrs96))
                // Pack 45 chain outputs into 0x1C..0x2EB (748 bytes total input).
                // Safe overlap: pack[i] at 0x1C+16i never overwrites storage[i'] for i' > i
                // (verified: 0x80 + 32 i' > 0x3B + 16i whenever i' > i).
                for { let i := 0 } lt(i, 45) { i := add(i, 1) } {
                    mstore(add(0x1C, shl(4, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x2EC), N_MASK)

                //--- XMSS auth climb (h' = 4) ---
                let authOff := add(sigOff, 720)    // 45 × 16
                let authPtr := add(sigBase, authOff)
                // ADRS base for XMSS_TREE: layer<<88 | curTree<<56 | 2<<48
                let xmssBase96 := or(or(shl(88, layer), shl(56, curTree)), shl(48, 2))
                let merkleNode := wotsPk
                let mIdx := curLeaf
                for { let h := 0 } lt(h, 4) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    let hp1 := add(h, 1)
                    let adrs96 := or(xmssBase96, or(shl(16, hp1), parentIdx))
                    mstore(0x10, shl(160, adrs96))
                    switch and(mIdx, 1)
                    case 0 {
                        mstore(0x1C, merkleNode)
                        mstore(0x2C, sibling)
                    }
                    default {
                        mstore(0x1C, sibling)
                        mstore(0x2C, merkleNode)
                    }
                    merkleNode := and(keccak256(0x00, 0x3C), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff      := add(authOff, 64)   // + 4 × 16

                // Advance: leaf = tree & 0xF; tree = tree >> 4
                curLeaf := and(curTree, 0xF)
                curTree := shr(4, curTree)
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
