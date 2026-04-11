// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinForsCVerifier — FORS+C-only verifier with unbalanced Merkle tree
/// @dev JARDÍN compact path variant 2: k=26, a=5, n=16 bytes (128-bit).
///      Verifies FORS+C signature + walks unbalanced tree auth path to pkRoot.
///      H_msg: 192-byte domain-separated hash (seed||root||R||msg||counter||domain).
///      ~66K gas for FORS+C verification + ~2K gas per unbalanced auth node.
///
///      Signature layout (variable length, 2452 + q*16 bytes):
///        R(32) | counter(4) | 25 × (secret 16B + auth 5×16B) | lastRoot(16) | q × auth(16)
contract JardinForsCVerifier {

    function verifyForsCUnbalanced(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external pure returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ── Validate signature length ──
            // Min: R(32) + counter(4) + 25*96 + lastRoot(16) + 1*auth(16) = 2468
            if lt(sig.length, 2468) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // Auth path bytes must be positive multiple of 16
            let authBytes := sub(sig.length, 2452)
            if mod(authBytes, 16) { revert(0, 0) }
            let q := div(authBytes, 16)
            if iszero(q) { revert(0, 0) }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── H_msg (192 bytes): seed || root || R || message || counter || domain ──
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, calldataload(sigBase))                    // R (32 bytes)
            mstore(0x60, message)
            mstore(0x80, shr(224, calldataload(add(sigBase, 32)))) // counter (4B)
            mstore(0xA0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let dVal := keccak256(0x00, 0xC0)

            // ── Forced-zero: tree 25 index (bits 125-129) must be 0 ──
            // last_shift = (K-1)*A = 25*5 = 125
            if and(shr(125, dVal), 0x1F) { revert(0, 0) }

            // ── FORS+C verification: K=26, A=5, K-1=25 normal trees ──
            // Each tree: secret(16) + auth(5*16=80) = 96 bytes
            // Sig body starts at offset 36 (after R=32 + counter=4)
            let forsBase := add(sigBase, 36)

            for { let i := 0 } lt(i, 25) { i := add(i, 1) } {
                // Extract 5-bit FORS index for tree i
                let treeIdx := and(shr(mul(i, 5), dVal), 0x1F)

                // Secret at forsBase + i*96
                let treeOff := add(forsBase, mul(i, 96))
                let secretVal := and(calldataload(treeOff), N_MASK)

                // Hash leaf: th(seed, leafAdrs, secret)
                // leafAdrs: atype=3, kp=i, ci=q, ha=treeIdx
                mstore(0x00, seed)
                mstore(0x20, or(or(shl(128, 3), shl(96, i)), or(shl(64, q), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Walk A=5 auth path levels
                let treeAdrsBase := or(or(shl(128, 3), shl(96, i)), shl(64, q))
                let pathIdx := treeIdx
                let authPtr := add(treeOff, 16)

                for { let h := 0 } lt(h, 5) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    // Branchless Merkle swap
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Store tree root at 0x80 + i*32
                mstore(add(0x80, shl(5, i)), node)
            }

            // ── Last tree (tree 25, forced-zero): hash the provided root ──
            {
                // lastRoot at forsBase + 25*96 = forsBase + 2400
                let lastRootOff := add(forsBase, 2400)
                let lastRootVal := and(calldataload(lastRootOff), N_MASK)
                // th(seed, leafAdrs(25, q, 0), lastRootVal)
                mstore(0x00, seed)
                mstore(0x20, or(or(shl(128, 3), shl(96, 25)), shl(64, q)))
                mstore(0x40, lastRootVal)
                // Store at slot 25: 0x80 + 25*32 = 0x80 + 0x320 = 0x3A0
                mstore(0x3A0, and(keccak256(0x00, 0x60), N_MASK))
            }

            // ── Compress 26 FORS roots ──
            // keccak256(seed || rootsAdrs || 26 roots) = 32+32+26*32 = 896 = 0x380
            mstore(0x00, seed)
            // rootsAdrs: atype=4, ci=q
            mstore(0x20, or(shl(128, 4), shl(64, q)))
            for { let i := 0 } lt(i, 26) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x380), N_MASK)

            // ── Unbalanced tree auth path walk ──
            let unbNode := forsPk
            let authStart := add(sigBase, 2452)

            // Step 0: auth[0] is LEFT sibling, unbNode is RIGHT
            {
                let authNode := and(calldataload(authStart), N_MASK)
                mstore(0x00, seed)
                mstore(0x20, or(shl(128, 6), shl(32, sub(q, 1))))
                mstore(0x40, authNode)
                mstore(0x60, unbNode)
                unbNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            // Steps 1..q-1: unbNode is LEFT, auth[j] is RIGHT
            for { let j := 1 } lt(j, q) { j := add(j, 1) } {
                let authNode := and(calldataload(add(authStart, shl(4, j))), N_MASK)
                let depth := sub(sub(q, 1), j)
                mstore(0x20, or(shl(128, 6), shl(32, depth)))
                mstore(0x40, unbNode)
                mstore(0x60, authNode)
                unbNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            // ── Final root comparison ──
            valid := eq(unbNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
