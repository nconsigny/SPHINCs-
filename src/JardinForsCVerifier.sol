// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinForsCVerifier — FORS+C verifier with balanced h=7 Merkle tree
/// @dev JARDÍN compact path variant 2: k=26, a=5, n=16 bytes (128-bit).
///      Verifies FORS+C signature and walks a balanced Merkle tree of height
///      h=7 (Q_MAX=128) up to pkRoot. Auth path is a constant 7 nodes.
///      H_msg: 192-byte domain-separated hash (seed||root||R||msg||counter||domain).
///
///      Signature layout (constant 2565 bytes):
///        R(32) | counter(4) | 25 × (secret 16B + auth 5×16B) | lastRoot(16)
///        | q(1) | merkleAuth(7×16)
contract JardinForsCVerifier {

    function verifyForsC(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external pure returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ── Validate signature length (constant) ──
            // 32 + 4 + 25*96 + 16 + 1 + 7*16 = 2565
            if iszero(eq(sig.length, 2565)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── Read explicit 1-byte q at offset 2452 (after FORSC_BODY) ──
            let q := shr(248, calldataload(add(sigBase, 2452)))
            if or(iszero(q), gt(q, 128)) { revert(0, 0) }
            let leafIdx := sub(q, 1)

            // ── H_msg (192 bytes): seed || root || R || message || counter || domain ──
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, calldataload(sigBase))                    // R (32 bytes)
            mstore(0x60, message)
            mstore(0x80, shr(224, calldataload(add(sigBase, 32)))) // counter (4B)
            mstore(0xA0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let dVal := keccak256(0x00, 0xC0)

            // ── Forced-zero: tree 25 index (bits 125-129) must be 0 ──
            if and(shr(125, dVal), 0x1F) { revert(0, 0) }

            // ── FORS+C verification: K=26, A=5, K-1=25 normal trees ──
            // ADRS convention (FIPS 205): kp=0, ci=q, x=treeHeight, y=continuous
            // index across all k trees. For tree i at height z with local parent
            // index p, global y = (i << (A - z)) | p.
            let forsBase := add(sigBase, 36)
            let adrsForsCq := or(shl(128, 3), shl(64, q))

            for { let i := 0 } lt(i, 25) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 5), dVal), 0x1F)

                let treeOff := add(forsBase, mul(i, 96))
                let secretVal := and(calldataload(treeOff), N_MASK)

                // Leaf ADRS: x=0, y = (i << 5) | treeIdx
                mstore(0x20, or(adrsForsCq, or(shl(5, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                let authPtr := add(treeOff, 16)

                for { let h := 0 } lt(h, 5) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // Height = h+1; global y = (i << (4-h)) | parentIdx
                    let globalY := or(shl(sub(4, h), i), parentIdx)
                    mstore(0x20, or(adrsForsCq, or(shl(32, add(h, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // ── Last tree (tree 25, forced-zero): hash the provided root ──
            // Leaf ADRS: x=0, y = 25 << 5 = 800
            {
                let lastRootOff := add(forsBase, 2400)
                let lastRootVal := and(calldataload(lastRootOff), N_MASK)
                mstore(0x20, or(adrsForsCq, shl(5, 25)))
                mstore(0x40, lastRootVal)
                mstore(0x3A0, and(keccak256(0x00, 0x60), N_MASK))
            }

            // ── Compress 26 FORS roots ──
            mstore(0x20, or(shl(128, 4), shl(64, q)))
            for { let i := 0 } lt(i, 26) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x380), N_MASK)

            // ── Balanced Merkle walk (h=7) ──
            // Auth path at sigBase + 2453 (after 2452-byte body + 1 byte q)
            // Type=16 JARDIN_MERKLE, x=level, y=parentIndex, ci=0, kp=0
            let authStart := add(sigBase, 2453)
            let adrsMerkle := shl(128, 16)
            let merkleNode := forsPk

            for { let j := 0 } lt(j, 7) { j := add(j, 1) } {
                let sibling := and(calldataload(add(authStart, shl(4, j))), N_MASK)
                let level := sub(6, j)                 // h - 1 - j
                let parentIdx := shr(add(j, 1), leafIdx)
                mstore(0x20, or(adrsMerkle, or(shl(32, level), parentIdx)))
                // L/R ordering from bit j of leafIdx: 0 → node left, 1 → node right
                let s := shl(5, and(shr(j, leafIdx), 1))
                mstore(xor(0x40, s), merkleNode)
                mstore(xor(0x60, s), sibling)
                merkleNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            // ── Final root comparison ──
            valid := eq(merkleNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
