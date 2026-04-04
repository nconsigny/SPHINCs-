// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsWcPfp20Asm - Assembly-optimized SPHINCS+ Verifier: W+C + P+FP
/// @notice Contract 5 Asm: h=20, d=2, a=12, k=11, treeHeight=16, w=32, l=25, S_{w,n}=388, z=0, mMax=98
///         Sig: 2888 bytes. Same external interface as SphincsWcPfp20.
/// @dev Fixed memory layout:
///        0x00:  seed (warm forever)
///        0x20:  ADRS scratch
///        0x40:  input1 / left child
///        0x60:  input2 / right child
///        0x80:  WOTS endpoint buffer (25×32) / leaf hashes (11×32) / FORS roots
///        0x1E0: PORS indices (11×32)
///        0x3C0: scratch for idxTree spill, 0x3E0: sigOff spill
///        0x400: Octopus working set ((K)*64 max)
contract SphincsWcPfp20Asm {
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

            // Verify sig length = 2888
            if iszero(eq(calldataload(0x44), 2888)) {
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

            // htIdx = (digest >> 132) & (2^20-1)
            let htIdx := and(shr(132, digest), 0xFFFFF)

            // ============================================================
            // STEP 2: PORS+FP verification
            // ============================================================
            // K=11 leaves, TREE_HEIGHT=16, mMax=98
            // PORS_START=16, AUTH_START=16+11*16=192, HT_START=192+98*16=1760

            // 2a: Extract 11 distinct indices from digest.
            // Indices stored at 0x1E0 (= 0x80 + 11*32), leaf hashes at 0x80.
            let INDICES_BASE := 0x1E0
            {
                let totalLeaves := 65536 // 2^16
                let idxMask := 0xFFFF    // 2^16 - 1
                let count := 0
                let nonce := 0

                for { } lt(count, 11) { } {
                    // extended = keccak256(digest || nonce) — use 0x20..0x5F as scratch
                    mstore(0x20, digest)
                    mstore(0x40, nonce)
                    let extended := keccak256(0x20, 0x40)

                    let bits := extended
                    for { let b := 0 } and(lt(add(b, 16), 257), lt(count, 11)) { b := add(b, 16) } {
                        let candidate := and(shr(b, bits), idxMask)
                        if lt(candidate, totalLeaves) {
                            // Check duplicates
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

                // Hash secrets into leaf hashes using digest-derived indices.
                for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                    let secretVal := and(calldataload(add(SIG_BASE, add(16, mul(i, 16)))), N_MASK)
                    let leafIdx := mload(add(INDICES_BASE, mul(i, 0x20)))
                    mstore(0x20, or(shl(128, 5), leafIdx))
                    mstore(0x40, secretVal)
                    mstore(add(0x80, mul(i, 0x20)), and(keccak256(0x00, 0x60), N_MASK))
                }

                // Insertion sort indices AND co-sort leaf hashes at 0x80
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

            // 2c: Octopus reconstruction
            // Working set at 0x400: (index:32, hash:32) per entry = 64 bytes each
            let OCTOPUS := 0x400
            // Initialize with sorted (index, leafHash) pairs
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(add(OCTOPUS, mul(i, 0x40)), mload(add(INDICES_BASE, mul(i, 0x20))))
                mstore(add(OCTOPUS, add(mul(i, 0x40), 0x20)), mload(add(0x80, mul(i, 0x20))))
            }

            let currentCount := 11
            let authIdx := 0

            for { let level := 0 } lt(level, 16) { level := add(level, 1) } {
                let newCount := 0
                let j := 0

                for { } lt(j, currentCount) { } {
                    let idx := mload(add(OCTOPUS, mul(j, 0x40)))
                    let hashJ := mload(add(OCTOPUS, add(mul(j, 0x40), 0x20)))
                    let sibling := xor(idx, 1)
                    let parent := shr(1, idx)

                    // ADRS: type=TREE(2), height=level+1, index=parent
                    mstore(0x20, or(shl(128, 2), or(shl(32, add(level, 1)), parent)))

                    // Check if next node is sibling
                    let hasSib := 0
                    if lt(add(j, 1), currentCount) {
                        if eq(mload(add(OCTOPUS, mul(add(j, 1), 0x40))), sibling) {
                            hasSib := 1
                        }
                    }

                    switch hasSib
                    case 1 {
                        let hashJ1 := mload(add(OCTOPUS, add(mul(add(j, 1), 0x40), 0x20)))
                        // Order by index parity
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
                        if iszero(lt(authIdx, 98)) { revert(0, 0) }
                        // Read sibling from auth set: AUTH_START + authIdx*16 = 192 + authIdx*16
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

            // Verify root reached
            if or(iszero(eq(currentCount, 1)), iszero(eq(mload(OCTOPUS), 0))) {
                revert(0, 0)
            }
            let porsPk := mload(add(OCTOPUS, 0x20))

            // ============================================================
            // STEP 3: Hypertree (D=2 layers of WOTS+C + Merkle)
            // ============================================================
            let currentNode := porsPk
            let idxTree := htIdx
            let sigOff := 1760 // HT_START = 192 + 98*16

            // Spill to memory to free stack
            mstore(0x3C0, idxTree)
            mstore(0x3E0, sigOff)

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                idxTree := mload(0x3C0)
                sigOff := mload(0x3E0)

                let idxLeaf := and(idxTree, 0x3FF)  // 2^10 - 1
                idxTree := shr(10, idxTree)

                // WOTS ADRS
                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

                // Read count (4 bytes after 25*16=400 bytes of WOTS sigma)
                let countOff := add(sigOff, 400) // 25*16
                let count := shr(224, calldataload(add(SIG_BASE, countOff)))

                // WOTS digest
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate digit sum = 388
                // Extract 25 base-32 digits (5 bits each) and sum them
                let digitSum := 0
                for { let ii := 0 } lt(ii, 25) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 5), d), 0x1F))
                }
                if iszero(eq(digitSum, 388)) { revert(0, 0) }

                // Complete 25 chains
                for { let i := 0 } lt(i, 25) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 5), d), 0x1F)
                    let steps := sub(31, digit)  // w-1-digit
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

                // PK compression: keccak256(seed || pkAdrs || 25 endpoints)
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 25) { i := add(i, 1) } {
                    mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                }
                // Total: 32(seed) + 32(adrs) + 25*32(endpoints) = 864 bytes = 0x360
                let wotsPk := and(keccak256(0x00, 0x360), N_MASK)

                // Merkle auth path (h=10)
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

                // Save updated state
                mstore(0x3C0, idxTree)
                mstore(0x3E0, add(authOff, mul(10, 16)))
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
