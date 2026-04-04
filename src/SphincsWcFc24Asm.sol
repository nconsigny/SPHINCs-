// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsWcFc24Asm - Assembly-optimized SPHINCS+ Verifier: W+C + FORS+C
/// @notice Contract 6 Asm: h=24, d=2, a=16, k=8, w=16, l=32, S_{w,n}=240, z=0
///         Sig: 3352 bytes. Same external interface as SphincsWcFc24.
/// @dev Fixed memory layout:
///        0x00: seed (warm forever)
///        0x20: ADRS scratch
///        0x40: input1 / left child
///        0x60: input2 / right child
///        0x80: WOTS endpoint buffer (32×32) / FORS roots buffer (8×32)
contract SphincsWcFc24Asm {
    bytes32 public pkSeed;  // slot 0
    bytes32 public pkRoot;  // slot 1

    constructor(bytes32 _seed, bytes32 _root) {
        pkSeed = _seed;
        pkRoot = _root;
    }

    function verify(bytes32 message, bytes calldata sig) external view returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            let SIG_BASE := 0x64

            // Verify sig length = 3352
            if iszero(eq(calldataload(0x44), 3352)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // ============================================================
            // STEP 0: Load seed/root, setup memory
            // ============================================================
            let seed := sload(0)
            let root := sload(1)
            mstore(0x00, seed)

            // ============================================================
            // STEP 1: H_msg digest
            // ============================================================
            let R := and(calldataload(SIG_BASE), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, calldataload(0x04))
            let digest := keccak256(0x00, 0x80)

            // htIdx = (digest >> 128) & (2^24-1)
            let htIdx := and(shr(128, digest), 0xFFFFFF)

            // ============================================================
            // STEP 2: FORS+C verification
            // ============================================================
            // K=8, A=16, K-1=7 trees + 1 forced-zero tree
            // FORS_START=16, AUTH_START=16+8*16=144, HT_START=144+7*16*16=1936

            let dVal := digest

            // Check forced-zero: last index (i=7) must be 0
            // bits 112..127 of digest
            let lastIdx := and(shr(112, dVal), 0xFFFF)
            if lastIdx { revert(0, 0) }

            // Process K-1=7 trees with auth paths
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 16), dVal), 0xFFFF)

                // Read secret: FORS_START + i*16 = 16 + i*16
                let secretVal := and(calldataload(add(SIG_BASE, add(16, mul(i, 16)))), N_MASK)

                // Leaf ADRS: type=FORS_TREE(3), keyPair=i, hashAddr=treeIdx
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx

                // Auth path: AUTH_START + i*A*N = 144 + i*256
                let authBase := add(144, mul(i, 256))

                // Walk A=16 auth path levels
                for { let h := 0 } lt(h, 16) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(SIG_BASE, add(authBase, mul(h, 16)))), N_MASK)
                    let parentIdx := shr(1, pathIdx)

                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))

                    let bit := and(pathIdx, 1)
                    mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                    node := and(keccak256(0x00, 0x80), N_MASK)

                    pathIdx := parentIdx
                }

                // Store root
                mstore(add(0x80, mul(i, 0x20)), node)
            }

            // Last tree (k-1=7): forced index=0, secret is tree root
            {
                let lastSecret := and(calldataload(add(SIG_BASE, add(16, mul(7, 16)))), N_MASK)
                // ADRS: type=FORS_TREE(3), keyPair=7
                mstore(0x20, or(shl(128, 3), shl(96, 7)))
                mstore(0x40, lastSecret)
                let lastRoot := and(keccak256(0x00, 0x60), N_MASK)
                mstore(add(0x80, mul(7, 0x20)), lastRoot)
            }

            // Compress 8 roots: keccak256(seed || rootsAdrs || 8 roots)
            // rootsAdrs: type=FORS_ROOTS(4)
            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
            }
            // 32 + 32 + 8*32 = 320 = 0x140
            let forsPk := and(keccak256(0x00, 0x140), N_MASK)

            // ============================================================
            // STEP 3: Hypertree (D=2 layers of WOTS+C + Merkle)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 1936 // HT_START = 144 + 7*256

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0xFFF) // 2^12 - 1
                idxTree := shr(12, idxTree)

                // WOTS ADRS
                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

                // Read count at sigOff + 32*16 = sigOff + 512
                let countOff := add(sigOff, 512)
                let count := shr(224, calldataload(add(SIG_BASE, countOff)))

                // WOTS digest
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate digit sum = 240
                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
                }
                if iszero(eq(digitSum, 240)) { revert(0, 0) }

                // Complete 32 chains
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 4), d), 0xF)
                    let steps := sub(15, digit)
                    let val := and(calldataload(add(SIG_BASE, add(sigOff, mul(i, 16)))), N_MASK)

                    let chainAdrs := or(wotsAdrs, shl(64, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        let pos := add(digit, step)
                        mstore(0x20, or(
                            and(chainAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                            shl(32, pos)
                        ))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }

                    mstore(add(0x80, mul(i, 0x20)), val)
                }

                // PK compression: keccak256(seed || pkAdrs || 32 endpoints)
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                }
                let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

                // Merkle auth path (h=12)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf

                for { let h := 0 } lt(h, 12) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(SIG_BASE, add(authOff, mul(h, 16)))), N_MASK)
                    let parentIdx := shr(1, mIdx)

                    mstore(0x20, or(
                        and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                        or(shl(32, add(h, 1)), parentIdx)
                    ))

                    let bit := and(mIdx, 1)
                    mstore(0x40, xor(merkleNode, mul(xor(merkleNode, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, merkleNode), bit)))
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)

                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, mul(12, 16))
            }

            // ============================================================
            // STEP 4: Return
            // ============================================================
            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
