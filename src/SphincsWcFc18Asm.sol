// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsWcFc18Asm - Assembly-optimized SPHINCS+ Verifier: W+C + FORS+C
/// @notice Contract 2 Asm: h=18, d=2, a=13, k=13, w=16, l=39, S_{w,n}=292, z=0
///         Sig: 4264 bytes. Same external interface as SphincsWcFc18.
/// @dev Full assembly verification with fixed memory layout:
///        0x00: seed (written once, warm forever)
///        0x20: ADRS (modified in-place)
///        0x40: input1 / left child
///        0x60: input2 / right child
///        0x80: WOTS endpoint buffer / FORS roots buffer (39×32 = 1248 bytes)
///      No memory arrays allocated. No library calls. No free pointer usage.
contract SphincsWcFc18Asm {
    bytes32 public pkSeed;  // slot 0
    bytes32 public pkRoot;  // slot 1

    constructor(bytes32 _seed, bytes32 _root) {
        pkSeed = _seed;
        pkRoot = _root;
    }

    /// @notice Verify a W+C + FORS+C signature
    /// @param message The signed message hash
    /// @param sig The signature bytes (4264 bytes)
    /// @return valid True if signature is valid
    function verify(bytes32 message, bytes calldata sig) external view returns (bool valid) {
        assembly ("memory-safe") {
            // ============================================================
            // CONSTANTS
            // ============================================================
            // N=16 bytes, mask for top 128 bits
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // Signature layout (byte offsets within sig)
            // FORS_START = 16, AUTH_START = 16+13*16 = 224
            // HT_START = 224 + 12*13*16 = 224 + 2496 = 2720
            // LAYER_SIZE = 39*16 + 4 + 9*16 = 624 + 4 + 144 = 772
            // SIG_SIZE = 2720 + 2*772 = 4264

            // Calldata layout: selector(4) + message(32) + offset(32) + length(32) + sig_bytes
            // sig_bytes starts at calldata offset = 4 + 32 + 32 + 32 = 100 = 0x64
            let SIG_BASE := 0x64

            // Verify signature length
            // sig.length is at calldataload(0x44)
            let sigLen := calldataload(0x44)
            if iszero(eq(sigLen, 4264)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            // ============================================================
            // STEP 0: Load seed and root, set up memory
            // ============================================================
            let seed := sload(0)   // pkSeed
            let root := sload(1)   // pkRoot

            // Write seed to 0x00 — remains warm for all subsequent keccak calls
            mstore(0x00, seed)

            // ============================================================
            // STEP 1: Read R, compute H_msg digest
            // ============================================================
            // R = sig[0..15], left-aligned in bytes32
            let R := and(calldataload(SIG_BASE), N_MASK)

            // digest = keccak256(seed || root || R || message)
            // seed already at 0x00
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, calldataload(0x04))  // message
            let digest := keccak256(0x00, 0x80)

            // Restore seed at 0x00 (keccak didn't modify memory, but let's be safe
            // for subsequent operations — actually keccak256 only reads, so 0x00 still has seed)

            // ============================================================
            // STEP 2: Extract hypertree index from digest
            // ============================================================
            // htIdx = bits [169..186] of digest = (digest >> 169) & (2^18 - 1)
            // 169 = K*A = 13*13
            let htIdx := and(shr(169, digest), 0x3FFFF) // 2^18 - 1 = 0x3FFFF

            // ============================================================
            // STEP 3: FORS+C verification
            // ============================================================
            // Extract K=13 indices from digest, each A=13 bits
            let dVal := digest
            // let aMask := 0x1FFF // 2^13 - 1

            // Check forced-zero: last index (i=12) must be 0
            let lastIdx := and(shr(156, dVal), 0x1FFF) // 12*13 = 156
            if lastIdx {
                revert(0, 0) // FORS+C forced-zero violated
            }

            // Process K-1=12 trees with auth paths, then last tree special
            // Store roots at 0x80 + i*32 for final thMulti

            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                // Extract tree index for tree i
                let treeIdx := and(shr(mul(i, 13), dVal), 0x1FFF)

                // Read secret from calldata: FORS_START + i*16 = 16 + i*16
                let secretVal := and(calldataload(add(SIG_BASE, add(16, mul(i, 16)))), N_MASK)

                // Leaf ADRS: type=FORS_TREE(3), keyPair=i, hashAddr=treeIdx
                // ADRS = (3 << 128) | (i << 96) | treeIdx
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                // th(seed, leafAdrs, secret) = keccak256(0x00, 0x60) masked
                let node := and(keccak256(0x00, 0x60), N_MASK)

                // Tree ADRS base: type=FORS_TREE(3), keyPair=i
                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx

                // Auth path base in sig: AUTH_START + i*A*N = 224 + i*13*16 = 224 + i*208
                let authBase := add(224, mul(i, 208))

                // Walk A=13 auth path levels
                for { let h := 0 } lt(h, 13) { h := add(h, 1) } {
                    // Read sibling from calldata
                    let sibling := and(calldataload(add(SIG_BASE, add(authBase, mul(h, 16)))), N_MASK)
                    let parentIdx := shr(1, pathIdx)

                    // ADRS: treeAdrsBase | (height << 32) | parentIdx
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))

                    // Branchless left/right ordering
                    let bit := and(pathIdx, 1)
                    mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                    node := and(keccak256(0x00, 0x80), N_MASK)

                    pathIdx := parentIdx
                }

                // Store root at 0x80 + i*32
                mstore(add(0x80, mul(i, 0x20)), node)
            }

            // Last tree (k-1=12): forced index=0, just hash secret
            {
                let lastSecret := and(calldataload(add(SIG_BASE, add(16, mul(12, 16)))), N_MASK)
                // ADRS: type=FORS_TREE(3), keyPair=12
                mstore(0x20, or(shl(128, 3), shl(96, 12)))
                mstore(0x40, lastSecret)
                let lastRoot := and(keccak256(0x00, 0x60), N_MASK)
                mstore(add(0x80, mul(12, 0x20)), lastRoot)
            }

            // Compress 13 roots: thMulti(seed, rootsAdrs, roots[0..12])
            // rootsAdrs: type=FORS_ROOTS(4) = (4 << 128)
            mstore(0x20, shl(128, 4))
            // Roots are at 0x80..0x80+13*32 = 0x80..0x220
            // keccak256(seed(0x00) + adrs(0x20) + 13 roots(0x80..0x220))
            // Total length = 32 + 32 + 13*32 = 480 = 0x1E0
            // But roots start at 0x80 which is after adrs at 0x20..0x3F
            // We need seed || adrs || root0 || root1 || ... || root12 contiguous
            // seed is at 0x00, adrs at 0x20, roots at 0x80 — GAP at 0x40..0x7F!
            // Solution: either shift roots down or copy seed+adrs up.
            // Better: copy roots from 0x80 to 0x40 (overwriting scratch)
            // Then keccak256(0x00, 0x40 + 13*32) = keccak256(0x00, 0x40 + 0x1A0) = keccak256(0x00, 0x1E0)
            for { let i := 0 } lt(i, 13) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
            }
            let forsPk := and(keccak256(0x00, 0x1E0), N_MASK) // 32+32+13*32 = 480

            // ============================================================
            // STEP 4: Hypertree verification (D=2 layers)
            // ============================================================
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 2720 // HT_START

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0x1FF) // 2^9 - 1
                idxTree := shr(9, idxTree)

                // ---- WOTS+C VERIFICATION ----

                // WOTS ADRS: layer | (idxTree << 160) | (idxLeaf << 96)
                // type=WOTS(0), so type field is 0
                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

                // Read count: at sigOff + 39*16 = sigOff + 624
                let countOff := add(sigOff, 624)
                let count := shr(224, calldataload(add(SIG_BASE, countOff)))

                // Compute WOTS digest: keccak256(seed || hashAdrs || currentNode || count)
                mstore(0x20, wotsAdrs) // hashAdrs = wotsAdrs with type=0 (same)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Extract 39 base-16 digits, validate sum = 292
                let digitSum := 0
                for { let ii := 0 } lt(ii, 39) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
                }
                if iszero(eq(digitSum, 292)) {
                    revert(0, 0) // WOTS+C sum constraint violated
                }

                // Complete 39 chains, store endpoints at 0x80+i*32
                for { let i := 0 } lt(i, 39) { i := add(i, 1) } {
                    let digit := and(shr(mul(i, 4), d), 0xF)
                    let steps := sub(15, digit) // w-1-digit

                    // Read sigma_i from calldata: sigOff + i*16
                    let val := and(calldataload(add(SIG_BASE, add(sigOff, mul(i, 16)))), N_MASK)

                    // Chain ADRS: wotsAdrs | (chainIndex << 64)
                    let chainAdrs := or(wotsAdrs, shl(64, i))

                    // Chain hash loop
                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        let pos := add(digit, step)
                        // Set position in ADRS: clear bits [63..32], set pos
                        let adrsWord := or(
                            and(chainAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                            shl(32, pos)
                        )
                        mstore(0x20, adrsWord)
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }

                    // Store endpoint
                    mstore(add(0x80, mul(i, 0x20)), val)
                }

                // PK compression: thMulti(seed, pkAdrs, 39 endpoints)
                // pkAdrs: layer | tree | type=WOTS_PK(1) | keyPair
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                // Copy 39 endpoints from 0x80 to 0x40 for contiguous layout
                for { let i := 0 } lt(i, 39) { i := add(i, 1) } {
                    mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                }
                // keccak256(0x00, 32+32+39*32) = keccak256(0x00, 0x520)
                let wotsPk := and(keccak256(0x00, 0x520), N_MASK)

                // ---- MERKLE AUTH PATH ----
                let authOff := add(countOff, 4) // skip 4-byte count

                // treeAdrs: layer | tree | type=TREE(2)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf

                for { let h := 0 } lt(h, 9) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(SIG_BASE, add(authOff, mul(h, 16)))), N_MASK)
                    let parentIdx := shr(1, mIdx)

                    // ADRS: treeAdrs | (height << 32) | parentIdx
                    mstore(0x20, or(
                        and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                        or(shl(32, add(h, 1)), parentIdx)
                    ))

                    // Branchless left/right
                    let bit := and(mIdx, 1)
                    mstore(0x40, xor(merkleNode, mul(xor(merkleNode, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, merkleNode), bit)))
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)

                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(authOff, mul(9, 16)) // advance past auth path
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
