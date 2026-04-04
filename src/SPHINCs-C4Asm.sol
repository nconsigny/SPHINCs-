// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsC4Asm - Assembly-optimized SPHINCS+ Verifier: W+C + FORS+C
/// @notice Contract 4 Asm: h=30, d=3, a=14, k=8, w=16, l=32, S_{w,n}=240, z=0
///         Sig: 3740 bytes. Same external interface as SphincsC4.
contract SphincsC4Asm {
    bytes32 public pkSeed;  // slot 0
    bytes32 public pkRoot;  // slot 1

    constructor(bytes32 _seed, bytes32 _root) {
        pkSeed = _seed;
        pkRoot = _root;
    }

    /// @notice Verify a W+C + FORS+C signature
    /// @param message The signed message hash
    /// @param sig The signature bytes (3740 bytes)
    /// @return valid True if signature is valid
    function verify(bytes32 message, bytes calldata sig) external view returns (bool valid) {
        assembly ("memory-safe") {
            // ============================================================
            // CONSTANTS
            // ============================================================
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // Signature layout (byte offsets within sig)
            // FORS_START = 16, AUTH_START = 16+8*16 = 144
            // HT_START = 144 + 7*14*16 = 1712
            // LAYER_SIZE = 32*16 + 4 + 10*16 = 676
            // SIG_SIZE = 1712 + 3*676 = 3740
            let SIG_BASE := 0x64

            let sigLen := calldataload(0x44)
            if iszero(eq(sigLen, 3740)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // ============================================================
            // STEP 0: Load seed and root, set up memory
            // ============================================================
            let seed := sload(0)
            let root := sload(1)
            mstore(0x00, seed)

            // ============================================================
            // STEP 1: Read R, compute H_msg digest
            // ============================================================
            let R := and(calldataload(SIG_BASE), N_MASK)

            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, calldataload(0x04))
            let digest := keccak256(0x00, 0x80)

            // ============================================================
            // STEP 2: Extract hypertree index from digest
            // ============================================================
            // htIdx = bits [112..141] of digest = (digest >> 112) & (2^30 - 1)
            let htIdx := and(shr(112, digest), 0x3FFFFFFF)

            // ============================================================
            // STEP 3: FORS+C verification
            // ============================================================
            let dVal := digest

            // Check forced-zero: last index (i=7) must be 0
            let lastIdx := and(shr(98, dVal), 0x3FFF)
            if lastIdx {
                revert(0, 0)
            }

            // Process K-1=7 trees with auth paths
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 14), dVal), 0x3FFF)

                // secret offset: FORS_START + i*N = 16 + i*16
                let secretVal := and(calldataload(add(SIG_BASE, add(16, mul(i, 16)))), N_MASK)

                // leaf ADRS: type=FORS_TREE(3), keyPair=i, hashAddr=treeIdx
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx

                // AUTH_START + i*A*N = 144 + i*224
                let authBase := add(144, mul(i, 224))

                // A=14 levels
                for { let h := 0 } lt(h, 14) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(SIG_BASE, add(authBase, mul(h, 16)))), N_MASK)
                    let parentIdx := shr(1, pathIdx)

                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))

                    let bit := and(pathIdx, 1)
                    mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                    node := and(keccak256(0x00, 0x80), N_MASK)

                    pathIdx := parentIdx
                }

                mstore(add(0x80, mul(i, 0x20)), node)
            }

            // Last tree (k-1=7): forced index=0, hash secret only
            {
                let lastSecret := and(calldataload(add(SIG_BASE, add(16, mul(7, 16)))), N_MASK)
                mstore(0x20, or(shl(128, 3), shl(96, 7)))
                mstore(0x40, lastSecret)
                let lastRoot := and(keccak256(0x00, 0x60), N_MASK)
                mstore(add(0x80, mul(7, 0x20)), lastRoot)
            }

            // thMulti over 8 roots: len = 32 + 32 + 8*32 = 320 (0x140)
            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
            }
            let forsPk := and(keccak256(0x00, 0x140), N_MASK)

            // ============================================================
            // STEP 4: Hypertree verification (D=3 layers)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 1712

            for { let layer := 0 } lt(layer, 3) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x3FF) // 2^10 - 1
                idxTree := shr(10, idxTree)

                // ---- WOTS+C VERIFY ----
                // WOTS ADRS: layer | (idxTree << 160) | (idxLeaf << 96)
                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

                // count at sigOff + 32*16 = sigOff + 512
                let countOff := add(sigOff, 512)
                let count := shr(224, calldataload(add(SIG_BASE, countOff)))

                // d = H_msg(seed, hashAdrs, currentNode, count)
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // validate digit sum = 240
                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
                }
                if iszero(eq(digitSum, 240)) {
                    revert(0, 0)
                }

                // complete chains and store endpoints at 0x80 + i*32
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 4), d), 0xF)
                    let steps := sub(15, digit)

                    let val := and(calldataload(add(SIG_BASE, add(sigOff, mul(i, 16)))), N_MASK)
                    let chainAdrs := or(wotsAdrs, shl(64, i))

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        let pos := add(digit, step)
                        let adrsWord := or(
                            and(chainAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                            shl(32, pos)
                        )
                        mstore(0x20, adrsWord)
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }

                    mstore(add(0x80, mul(i, 0x20)), val)
                }

                // PK compression over 32 endpoints
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                }
                let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

                // ---- MERKLE AUTH PATH (SUBTREE_H=10) ----
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf

                for { let h := 0 } lt(h, 10) { h := add(h, 1) } {
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
                sigOff := add(authOff, 160) // 10*16
            }

            // ============================================================
            // STEP 5: Final root comparison
            // ============================================================
            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
