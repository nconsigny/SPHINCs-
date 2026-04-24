// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SLH-DSA-SHA2-128-24 — FIPS 205 / NIST SP 800-230 SLH-DSA-SHA2-128-24
/// @dev Bit-exact NIST compliance using the SHA-256 precompile (0x02).
///      Parameters (NIST SP 800-230 Table 1):
///        n  = 16   h = 22   d = 1   h' = 22
///        a  = 24   k = 6    w = 4 (lgw=2)   m = 21
///        l1 = 64   l2 = 4   l = 68
///        Sig = 3,856 bytes
///
///      Hash primitives (SHA-256, FIPS 205 §11.2.1, n=16 instance):
///        F     = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M1)[0..15]   — 102 B
///        H     = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M2)[0..15]   — 118 B
///        T_l   = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M)[0..15]    — variable
///        Hmsg  = MGF1-SHA-256(R ‖ PK.seed ‖ PK.root ‖ M, m=21)
///                  Single iteration: SHA-256(R ‖ seed ‖ root ‖ M ‖ I2OSP(0,4))[0..20]
///
///      ADRSc (compressed ADRS, 22 bytes, FIPS 205 §11.2):
///        layer(1) ‖ tree(8) ‖ type(1) ‖ <12-byte type-dependent field>
///        Type-dependent field (12 B):
///          WOTS_HASH (0): kp(4) ‖ chain(4) ‖ hash(4)
///          WOTS_PK   (1): kp(4) ‖ 0(8)
///          TREE      (2): 0(4)  ‖ height(4) ‖ index(4)
///          FORS_TREE (3): kp(4) ‖ height(4) ‖ index(4)
///          FORS_ROOTS(4): kp(4) ‖ 0(8)
///        For d=1 the layer and tree fields are always zero.
///
///      Signature layout (3,856 bytes):
///        R(16) | FORS = 6 × (sk 16 + auth 24·16) = 2,400 |
///                       HT  = 1 × (WOTS 68·16 + auth 22·16) = 1,440
///
///      Memory layout for F/H/T_l calls (constant prefix):
///        0x00..0x10  PK.seed value (16 B; bottom 16 B of this 32-B mstore = 0)
///        0x10..0x40  48 zero bytes (= bottom of seed-word + the 32-B zero word at 0x20)
///        0x40..0x56  ADRSc (top 22 B of the 32-B word stored at 0x40)
///        0x56..      payload (M, or L‖R, or roots concat)
///        SHA-256 output → 0x80 for F/H/T_k (32 B); → 0x4A0 for T_l (after large input).
contract SLH_DSA_SHA2_128_24_Verifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external view returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 3856)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ────────────── Hmsg (FIPS 205 §10.2, SHA-2 category 1) ──────────────
            //   inner = SHA-256(R ‖ seed ‖ root ‖ M)                              80 B
            //   Hmsg  = MGF1-SHA-256(R ‖ seed ‖ inner, 21)                        68 B
            //           (single iter since 21 ≤ 32:
            //            SHA-256(R ‖ seed ‖ inner ‖ I2OSP(0,4))[0..20])
            //
            // Inner call layout:
            //   0x00..0x10 = R bytes (top of mstore at 0x00; bottom 16 B gets overwritten)
            //   0x10..0x20 = seed (top 16 B of seed-word)
            //   0x20..0x30 = root (top 16 B of root-word)
            //   0x30..0x50 = M (full 32 B)
            // Write inner digest to 0x20 (overwrites root; seed at 0x10 preserved).
            mstore(0x00, calldataload(sigBase))   // R || calldata junk
            mstore(0x10, seed)                    // seed || zero (junk at 0x20 overwritten next)
            mstore(0x20, root)                    // root || zero
            mstore(0x30, message)                 // 32 B
            if iszero(staticcall(gas(), 0x02, 0x00, 0x50, 0x20, 0x20)) { revert(0, 0) }

            // Outer call layout (inner digest now at 0x20..0x40):
            //   0x00..0x10 = R (still there)
            //   0x10..0x20 = seed (still there)
            //   0x20..0x40 = inner (just written)
            //   0x40..0x44 = I2OSP(0, 4)
            mstore(0x40, 0)                       // 4 zero bytes (first 4 of the 32 B mstore)
            if iszero(staticcall(gas(), 0x02, 0x00, 0x44, 0x100, 0x20)) { revert(0, 0) }
            let dWord := mload(0x100)

            // Digest parsing — sphincs/sphincsplus reference (= PQClean)
            // convention, which is the industry SLH-DSA behaviour:
            //   md[t] : LSB-first bit-extraction within each byte
            //           = LITTLE-ENDIAN read of digest[3t..3t+3]
            //           = byte[3t] | byte[3t+1] << 8 | byte[3t+2] << 16
            //   leafIdx : big-endian read of digest[18..21] AND 0x3FFFFF
            //             = low 22 bits of the 24-bit BE value at bits 88..111
            //   (tree_idx is empty since d = 1)
            //
            // Computed per-tree inside the FORS loop below; leafIdx here:
            let leafIdx := and(shr(88, dWord), 0x3FFFFF)

            // ──────────── Set up the F/H/T_l prefix layout ────────────
            // PK.seed at 0x00 (top 16 = value, bottom 16 = 0); zeros at 0x20..0x40.
            mstore(0x00, seed)
            mstore(0x20, 0)

            // Pre-compute reusable ADRSc bases.
            //   forsBase = (3 << 176) | (leafIdx << 144)            (FORS_TREE, kp=leafIdx)
            //   wotsBase = (leafIdx << 144)                         (WOTS_HASH/PK, kp=leafIdx)
            //   forsRootsBase = (4 << 176) | (leafIdx << 144)       (FORS_ROOTS)
            //   wotsPkBase    = (1 << 176) | (leafIdx << 144)       (WOTS_PK)
            //   treeBase      = (2 << 176)                          (TREE)
            let forsBase := or(shl(176, 3), shl(144, leafIdx))
            let wotsBase := shl(144, leafIdx)
            let forsOff  := 16

            // ──────────────────────── FORS verify ────────────────────────
            for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                // md[t] = LE read of digest bytes 3t, 3t+1, 3t+2
                //       = byte_swap( BE read at word bits 232-24t .. 255-24t )
                // Equivalent: individual byte extractions below.
                let s := sub(232, mul(24, t))
                let mdT := or(or(
                    and(shr(add(s, 16), dWord), 0xFF),             // byte[3t]   at bits 0..7
                    shl(8,  and(shr(add(s, 8),  dWord), 0xFF))),   // byte[3t+1] at bits 8..15
                    shl(16, and(shr(s,          dWord), 0xFF)))    // byte[3t+2] at bits 16..23
                let treeOff := add(forsOff, mul(t, 400))
                let sk := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf F: ADRS.tree_height = 0, .tree_index = (t << a) | mdT
                mstore(0x40, or(forsBase, shl(80, or(shl(24, t), mdT))))
                mstore(0x56, sk)
                if iszero(staticcall(gas(), 0x02, 0x00, 0x66, 0x80, 0x20)) { revert(0, 0) }
                let node := and(mload(0x80), N_MASK)

                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, 24) { j := add(j, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, j))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    let globalY := or(shl(sub(23, j), t), parentIdx)
                    // ADRSc for H: tree_height = j+1, tree_index = globalY
                    mstore(0x40, or(forsBase, or(shl(112, add(j, 1)), shl(80, globalY))))
                    // Place L at 0x56 and R at 0x66.  Must write L FIRST, then R —
                    // mstore writes 32 bytes, so its bottom 16 land at the following
                    // slot.  If we wrote R (at 0x66) first then L (at 0x56), L's
                    // bottom 16 would overwrite R's value at 0x66.
                    switch and(pathIdx, 1)
                    case 0 { mstore(0x56, node)    mstore(0x66, sibling) }
                    default { mstore(0x56, sibling) mstore(0x66, node) }
                    if iszero(staticcall(gas(), 0x02, 0x00, 0x76, 0x80, 0x20)) { revert(0, 0) }
                    node := and(mload(0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x100 + t·32  (out of the 0x40..0x80 scratch zone)
                mstore(add(0x100, shl(5, t)), node)
            }

            // T_k: PKfors = SHA-256(seed ‖ zeros ‖ FORS_ROOTS-ADRSc ‖ roots[0..5])[0..15]
            // Input length = 16 + 48 + 22 + 6·16 = 182 = 0xB6
            mstore(0x40, or(shl(176, 4), shl(144, leafIdx)))
            // Pack roots from 0x100+t·32 (32-B slots) → 0x56+t·16 (packed 16-B).
            // Safe pattern: dst end (0x66+16t) < src start (0x80+32t) for all t≥0
            // (gap = 0x1A + 16t > 0).
            for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                mstore(add(0x56, shl(4, t)), mload(add(0x100, shl(5, t))))
            }
            if iszero(staticcall(gas(), 0x02, 0x00, 0xB6, 0x80, 0x20)) { revert(0, 0) }
            let currentNode := and(mload(0x80), N_MASK)

            // ──────────────────────── WOTS+ verify ────────────────────────
            let wotsPtr := add(sigBase, add(forsOff, 2400))   // R(16) + FORS(2400)

            // FIPS 205 base_2^b on currentNode (16-byte msg digest, MSB-first):
            //   currentNode holds the 128-bit value in its TOP 16 bytes (high 128 bits).
            //   digit[i] = (currentNode >> (254 - 2·i)) & 3   for i=0..63
            //   csum = Σ (3 - digit[i])         (max 192, fits 8 bits)
            //   csum_digits MSB-first from a single byte:
            //     csum_digit[j] = (csum >> (6 - 2·j)) & 3   for j=0..3
            let csum := 0

            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let digit := and(shr(sub(254, shl(1, i)), currentNode), 3)
                csum := add(csum, sub(3, digit))

                let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                let chainBase := or(wotsBase, shl(112, i))
                let steps := sub(3, digit)
                for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                    // ADRSc WOTS_HASH: kp=leafIdx, chain=i, hash=digit+s
                    mstore(0x40, or(chainBase, shl(80, add(digit, s))))
                    mstore(0x56, val)
                    if iszero(staticcall(gas(), 0x02, 0x00, 0x66, 0x80, 0x20)) { revert(0, 0) }
                    val := and(mload(0x80), N_MASK)
                }
                mstore(add(0x100, shl(5, i)), val)
            }

            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                let digit := and(shr(sub(6, shl(1, j)), csum), 3)
                let i := add(64, j)
                let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                let chainBase := or(wotsBase, shl(112, i))
                let steps := sub(3, digit)
                for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                    mstore(0x40, or(chainBase, shl(80, add(digit, s))))
                    mstore(0x56, val)
                    if iszero(staticcall(gas(), 0x02, 0x00, 0x66, 0x80, 0x20)) { revert(0, 0) }
                    val := and(mload(0x80), N_MASK)
                }
                mstore(add(0x100, shl(5, i)), val)
            }

            // T_l: WOTS_pk = SHA-256(seed ‖ zeros ‖ WOTS_PK-ADRSc ‖ tops[0..67])[0..15]
            // Input length = 16 + 48 + 22 + 68·16 = 1174 = 0x496
            mstore(0x40, or(shl(176, 1), shl(144, leafIdx)))
            for { let i := 0 } lt(i, 68) { i := add(i, 1) } {
                mstore(add(0x56, shl(4, i)), mload(add(0x100, shl(5, i))))
            }
            // Output to 0x4A0 (after the input area at 0x00..0x496).
            if iszero(staticcall(gas(), 0x02, 0x00, 0x496, 0x4A0, 0x20)) { revert(0, 0) }
            let wotsPk := and(mload(0x4A0), N_MASK)

            // ──────────────────────── XMSS climb (h' = 22) ────────────────────────
            let authPtr := add(wotsPtr, 1088)   // 68 × 16
            let merkleNode := wotsPk
            let mIdx := leafIdx
            for { let hh := 0 } lt(hh, 22) { hh := add(hh, 1) } {
                let sibling := and(calldataload(add(authPtr, shl(4, hh))), N_MASK)
                let parentIdx := shr(1, mIdx)
                // ADRSc TREE: type=2, kp=0, tree_height=hh+1, tree_index=parentIdx
                mstore(0x40, or(shl(176, 2), or(shl(112, add(hh, 1)), shl(80, parentIdx))))
                switch and(mIdx, 1)
                case 0 { mstore(0x56, merkleNode) mstore(0x66, sibling)    }
                default { mstore(0x56, sibling)    mstore(0x66, merkleNode) }
                if iszero(staticcall(gas(), 0x02, 0x00, 0x76, 0x80, 0x20)) { revert(0, 0) }
                merkleNode := and(mload(0x80), N_MASK)
                mIdx := parentIdx
            }

            valid := eq(merkleNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
