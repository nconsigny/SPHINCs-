// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsWcPfp27Asm - Assembly-optimized SPHINCS+ Verifier: W+C + P+FP
/// @notice Contract 3 Asm: h=27, d=3, a=11, k=11, w=16, l=32, S_{w,n}=240, z=0, mMax=68
///         Sig: 3260 bytes. Same external interface as SphincsWcPfp27.
contract SphincsWcPfp27Asm {
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

            // SIG_SIZE = N + K*N + mMax*N + D*(L*N + 4 + SH*N)
            //          = 16 + 11*16 + 68*16 + 3*(32*16+4+9*16)
            //          = 16 + 176 + 1088 + 3*660 = 1280 + 1980 = 3260
            if iszero(eq(calldataload(0x44), 3260)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := sload(0)
            let root := sload(1)
            mstore(0x00, seed)

            // H_msg digest
            let R := and(calldataload(SIG_BASE), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, calldataload(0x04))
            let digest := keccak256(0x00, 0x80)

            // htIdx: porsIdxBits = K*A = 11*11 = 121
            // htIdx = (digest >> 121) & (2^27 - 1)
            let htIdx := and(shr(121, digest), 0x7FFFFFF) // 2^27-1

            // ============================================================
            // PORS+FP: K=11, A=TREE_HEIGHT=11, mMax=68
            // PORS_START=16, AUTH_START=16+11*16=192, HT_START=192+68*16=1280
            // ============================================================

            // Extract 11 distinct indices from digest
            let INDICES_BASE := 0x240 // 0x80 + 11*32 = 0x80 + 0x160
            {
                let totalLeaves := 2048 // 2^11
                let idxMask := 0x7FF    // 2^11-1
                let count := 0
                let nonce := 0

                for { } lt(count, 11) { } {
                    mstore(0x20, digest)
                    mstore(0x40, nonce)
                    let extended := keccak256(0x20, 0x40)

                    let bits := extended
                    for { let b := 0 } and(lt(add(b, 11), 257), lt(count, 11)) { b := add(b, 11) } {
                        let candidate := and(shr(b, bits), idxMask)
                        if lt(candidate, totalLeaves) {
                            let dup := 0
                            for { let j := 0 } lt(j, count) { j := add(j, 1) } {
                                if eq(mload(add(INDICES_BASE, mul(j, 0x20))), candidate) {
                                    dup := 1
                                    j := count
                                }
                            }
                            if iszero(dup) {
                                mstore(add(INDICES_BASE, mul(count, 0x20)), candidate)
                                count := add(count, 1)
                            }
                        }
                    }
                    nonce := add(nonce, 1)
                }

                // Hash secrets using digest-derived leaf indices.
                for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                    let secretVal := and(calldataload(add(SIG_BASE, add(16, mul(i, 16)))), N_MASK)
                    let leafIdx := mload(add(INDICES_BASE, mul(i, 0x20)))
                    mstore(0x20, or(shl(128, 5), leafIdx))
                    mstore(0x40, secretVal)
                    mstore(add(0x80, mul(i, 0x20)), and(keccak256(0x00, 0x60), N_MASK))
                }

                // Insertion sort + co-sort hashes
                for { let ii := 1 } lt(ii, 11) { ii := add(ii, 1) } {
                    let keyIdx := mload(add(INDICES_BASE, mul(ii, 0x20)))
                    let keyHash := mload(add(0x80, mul(ii, 0x20)))
                    let jj := ii
                    for { } and(gt(jj, 0), gt(mload(add(INDICES_BASE, mul(sub(jj, 1), 0x20))), keyIdx)) { } {
                        mstore(add(INDICES_BASE, mul(jj, 0x20)),
                               mload(add(INDICES_BASE, mul(sub(jj, 1), 0x20))))
                        mstore(add(0x80, mul(jj, 0x20)),
                               mload(add(0x80, mul(sub(jj, 1), 0x20))))
                        jj := sub(jj, 1)
                    }
                    mstore(add(INDICES_BASE, mul(jj, 0x20)), keyIdx)
                    mstore(add(0x80, mul(jj, 0x20)), keyHash)
                }
            }

            // Octopus reconstruction at 0x560
            let OCTOPUS := 0x560
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(add(OCTOPUS, mul(i, 0x40)), mload(add(INDICES_BASE, mul(i, 0x20))))
                mstore(add(OCTOPUS, add(mul(i, 0x40), 0x20)), mload(add(0x80, mul(i, 0x20))))
            }

            mstore(0x00, seed) // restore seed

            let currentCount := 11
            let authIdx := 0

            for { let level := 0 } lt(level, 11) { level := add(level, 1) } {
                let newCount := 0
                let j := 0

                for { } lt(j, currentCount) { } {
                    let idx := mload(add(OCTOPUS, mul(j, 0x40)))
                    let hashJ := mload(add(OCTOPUS, add(mul(j, 0x40), 0x20)))
                    let sibling := xor(idx, 1)
                    let parent := shr(1, idx)

                    mstore(0x20, or(shl(128, 2), or(shl(32, add(level, 1)), parent)))

                    let hasSib := 0
                    if lt(add(j, 1), currentCount) {
                        if eq(mload(add(OCTOPUS, mul(add(j, 1), 0x40))), sibling) {
                            hasSib := 1
                        }
                    }

                    switch hasSib
                    case 1 {
                        let hashJ1 := mload(add(OCTOPUS, add(mul(add(j, 1), 0x40), 0x20)))
                        let bit := and(idx, 1)
                        mstore(0x40, xor(hashJ, mul(xor(hashJ, hashJ1), bit)))
                        mstore(0x60, xor(hashJ1, mul(xor(hashJ1, hashJ), bit)))
                        let parentHash := and(keccak256(0x00, 0x80), N_MASK)
                        mstore(add(OCTOPUS, mul(newCount, 0x40)), parent)
                        mstore(add(OCTOPUS, add(mul(newCount, 0x40), 0x20)), parentHash)
                        newCount := add(newCount, 1)
                        j := add(j, 2)
                    }
                    default {
                        // AUTH_START=192 for C3
                        let sibHash := and(calldataload(add(SIG_BASE, add(192, mul(authIdx, 16)))), N_MASK)
                        authIdx := add(authIdx, 1)

                        let bit := and(idx, 1)
                        mstore(0x40, xor(hashJ, mul(xor(hashJ, sibHash), bit)))
                        mstore(0x60, xor(sibHash, mul(xor(sibHash, hashJ), bit)))
                        let parentHash := and(keccak256(0x00, 0x80), N_MASK)
                        mstore(add(OCTOPUS, mul(newCount, 0x40)), parent)
                        mstore(add(OCTOPUS, add(mul(newCount, 0x40), 0x20)), parentHash)
                        newCount := add(newCount, 1)
                        j := add(j, 1)
                    }
                }
                currentCount := newCount
            }

            if or(iszero(eq(currentCount, 1)), iszero(eq(mload(OCTOPUS), 0))) {
                revert(0, 0)
            }
            let porsPk := mload(add(OCTOPUS, 0x20))

            // ============================================================
            // Hypertree: D=3 layers
            // ============================================================
            let currentNode := porsPk
            let idxTree := htIdx
            let sigOff := 1280 // HT_START = 192 + 68*16

            mstore(0x540, idxTree)
            mstore(0x560, sigOff)

            for { let layer := 0 } lt(layer, 3) { layer := add(layer, 1) } {
                idxTree := mload(0x540)
                sigOff := mload(0x560)

                let idxLeaf := and(idxTree, 0x1FF)
                idxTree := shr(9, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

                let countOff := add(sigOff, 512)
                let count := shr(224, calldataload(add(SIG_BASE, countOff)))

                mstore(0x00, seed)
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
                }
                if iszero(eq(digitSum, 240)) { revert(0, 0) }

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

                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                }
                let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf

                for { let h := 0 } lt(h, 9) { h := add(h, 1) } {
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
                mstore(0x540, idxTree)
                mstore(0x560, add(authOff, mul(9, 16)))
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
