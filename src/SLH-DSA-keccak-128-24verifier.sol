// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SLH-DSA-Keccak-128-24 — JARDIN-style Keccak variant of NIST SP 800-230
///        SLH-DSA-*-128-24 (2^24 signature limit, security category 1)
/// @dev Parameters (NIST SP 800-230 Table 1):
///        n  = 16      (128-bit security, keccak truncation)
///        h  = 22      (total hypertree height)
///        d  = 1       (single XMSS layer — no hypertree)
///        h' = 22      (per-layer height = 2^22 leaves)
///        a  = 24      (FORS tree height, 2^24 leaves per tree)
///        k  = 6       (FORS trees)
///        w  = 4       (Winternitz, lgw = 2)
///        m  = 21      (Hmsg bytes consumed)
///        l1 = 64, l2 = 4, l = 68  (WOTS+ chains, plain SLH-DSA checksum)
///
///      Signature layout (3,856 bytes, constant — matches NIST size):
///        R(16) | FORS(k=6 × (sk 16 + auth 24×16)) = 2,400
///              | Hypertree(d=1 × (WOTS 68×16 + XMSS auth 22×16)) = 1,440
///
///      JARDIN conventions preserved from JardinSpxVerifier:
///        - 32-byte ADRS (layer 4 | tree 8 | type 4 | kp 4 | ci 4 | cp 4 | ha 4)
///        - keccak256 truncated to 16B for F, H, T_l, T_k
///        - Hmsg = keccak(seed32 ‖ root32 ‖ R32 ‖ msg32 ‖ dom32)  [160 B]
///          R is 16B on wire, placed in the top 16B of a 32B word (low 16 = 0)
///          dom = 0xFF..FB (distinct from SPX 0xFF..FC, plain-FORS 0xFF..FD,
///                          T0 0xFF..FE, C11 0xFF..FF)
///        - LSB-first digest parsing:
///            md[t]   = (digest >> 24·t) & 0xFFFFFF      for t=0..5
///            leafIdx = (digest >> 144)  & 0x3FFFFF      (22 bits)
///            (treeIdx is empty since d=1)
contract SLH_DSA_Keccak_128_24_Verifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
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

            // ── Hmsg: keccak(seed ‖ root ‖ R_word ‖ msg ‖ dom=0xFF..FB) = 160 B ──
            // R is 16B on wire; load 32B and mask top 16B (R is MSB-aligned).
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, and(calldataload(sigBase), N_MASK))
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB)
            let dVal := keccak256(0x00, 0xA0)

            // LSB-first digest parsing (JARDIN family convention).
            // md[t] (24 bits each, t=0..5) occupies bits 0..143 of dVal.
            // leafIdx (22 bits) occupies bits 144..165.
            let leafIdx := and(shr(144, dVal), 0x3FFFFF)

            // Keep seed at 0x00 for every subsequent hash call.
            mstore(0x00, seed)

            // ───────────────────────── FORS ─────────────────────────
            // d=1 ⇒ treeIdx = 0. forsBase encodes: type=3, layer=0, tree=0, kp=leafIdx
            //   = shl(128, 3) | shl(96, leafIdx)
            let forsBase := or(shl(128, 3), shl(96, leafIdx))
            let forsOff  := 16   // R occupies the first 16 bytes of sig

            // FORS: 6 trees × (sk 16 + auth 24·16) = 6 × 400 = 2,400 B
            for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                let mdT      := and(shr(mul(24, t), dVal), 0xFFFFFF)
                let treeOff  := add(forsOff, mul(t, 400))
                let sk       := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << a) | mdT  — global y across 6 trees
                mstore(0x20, or(forsBase, or(shl(24, t), mdT)))
                mstore(0x40, sk)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, 24) { j := add(j, 1) } {
                    let sibling    := and(calldataload(add(authPtr, shl(4, j))), N_MASK)
                    let parentIdx  := shr(1, pathIdx)
                    // height = j+1;  global y = (t << (a - h)) | parent = (t << (23-j)) | parent
                    let globalY := or(shl(sub(23, j), t), parentIdx)
                    mstore(0x20, or(forsBase, or(shl(32, add(j, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x80 + t·0x20
                mstore(add(0x80, shl(5, t)), node)
            }

            // ── Compress 6 FORS roots: T_k(seed, FORS_ROOTS adrs, roots) ──
            // total = seed(32) + adrs(32) + 6·32 = 256 = 0x100
            {
                let adrsRoots := or(shl(128, 4), shl(96, leafIdx))
                mstore(0x20, adrsRoots)
                // Pack pattern: pack[t] at 0x40+t·32, storage[t] at 0x80+t·32.
                // Safe because pack[t] overwrites storage[t-2] which is already consumed.
                for { let t := 0 } lt(t, 6) { t := add(t, 1) } {
                    mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
                }
            }
            let currentNode := and(keccak256(0x00, 0x100), N_MASK)   // fors_pk

            // ─────────────────── Hypertree (d = 1 layer) ───────────────────
            // Single XMSS tree: layer=0, tree=0, leaf=leafIdx
            // WOTS ADRS base: type=0, layer=0, tree=0, kp=leafIdx
            let wotsBase := shl(96, leafIdx)
            let wotsPtr  := add(sigBase, add(forsOff, 2400))   // after R(16) + FORS(2400)

            // WOTS+ digits from currentNode (128-bit value in high 16B of word).
            //   msg_digit[i] (i=0..63) = (node >> (128 + 2i)) & 3   — LSB-first
            //   csum = Σ (3 - digit[i])                             — max 192, 8 bits
            //   csum_digit[j] (j=0..3) = (csum >> (6 - 2j)) & 3     — MSB-first per SLH-DSA
            //     (l2·lgw = 8 bits ⇒ already byte-aligned, no pre-shift needed)

            let csum := 0

            // ── 64 message-digit chains ──
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let digit := and(shr(add(128, shl(1, i)), currentNode), 3)
                csum := add(csum, sub(3, digit))

                let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                let chainBase := or(wotsBase, shl(64, i))   // ci = i
                let steps := sub(3, digit)
                for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                    mstore(0x20, or(chainBase, shl(32, add(digit, s))))
                    mstore(0x40, val)
                    val := and(keccak256(0x00, 0x60), N_MASK)
                }
                mstore(add(0x80, shl(5, i)), val)
            }

            // ── 4 checksum chains (i = 64, 65, 66, 67) ──
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                let digit := and(shr(sub(6, shl(1, j)), csum), 3)
                let i := add(64, j)
                let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                let chainBase := or(wotsBase, shl(64, i))
                let steps := sub(3, digit)
                for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                    mstore(0x20, or(chainBase, shl(32, add(digit, s))))
                    mstore(0x40, val)
                    val := and(keccak256(0x00, 0x60), N_MASK)
                }
                mstore(add(0x80, shl(5, i)), val)
            }

            // ── WOTS_PK compression via T_l (68 chain outputs) ──
            // total = seed(32) + adrs(32) + 68·32 = 2240 = 0x8C0
            {
                let pkAdrs := or(shl(128, 1), shl(96, leafIdx))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 68) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
            }
            let wotsPk := and(keccak256(0x00, 0x8C0), N_MASK)

            // ── XMSS auth climb (h' = 22) ──
            let authPtr := add(wotsPtr, 1088)   // 68 × 16
            // XMSS_TREE ADRS base: type=2, layer=0, tree=0, kp=0
            let xmssBase := shl(128, 2)
            let merkleNode := wotsPk
            let mIdx := leafIdx
            for { let hh := 0 } lt(hh, 22) { hh := add(hh, 1) } {
                let sibling   := and(calldataload(add(authPtr, shl(4, hh))), N_MASK)
                let parentIdx := shr(1, mIdx)
                mstore(0x20, or(xmssBase, or(shl(32, add(hh, 1)), parentIdx)))
                let s := shl(5, and(mIdx, 1))
                mstore(xor(0x40, s), merkleNode)
                mstore(xor(0x60, s), sibling)
                merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                mIdx := parentIdx
            }

            valid := eq(merkleNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
