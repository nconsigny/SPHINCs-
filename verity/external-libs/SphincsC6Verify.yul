// SPHINCS+ C6 Full Verification Oracle — linked Yul for Verity
// C6: W+C_F+C h=24 d=2 a=16 k=8 w=16 l=32 target_sum=240
// SIG_SIZE=3352 bytes
//
// sphincsC6Verify(sigOffset, message, seed) → computedRoot
// Implements: H_msg → FORS+C (k=8, a=16) → Hypertree (d=2, subtree_h=12) → root

function sphincsC6Verify(sigOffset, message, seed) -> computedRoot {
    let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

    // seed is already in the caller's memory at 0x00
    mstore(0x00, seed)

    // Read pkRoot from storage (needed for H_msg)
    let root := sload(1)

    // H_msg: keccak256(seed || root || R || message || domain) — 160 bytes
    let R := and(calldataload(sigOffset), N_MASK)
    mstore(0x20, root)
    mstore(0x40, R)
    mstore(0x60, message)
    mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    let digest := keccak256(0x00, 0xA0)

    let htIdx := and(shr(128, digest), 0xFFFFFF)

    // ---- FORS+C (K=8, A=16) ----
    let dVal := digest

    // Forced-zero: last FORS index (bits 112-127) must be 0
    if and(shr(112, dVal), 0xFFFF) { revert(0, 0) }

    // 7 normal FORS trees
    for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
        let treeIdx := and(shr(mul(i, 16), dVal), 0xFFFF)
        let secretVal := and(calldataload(add(sigOffset, add(16, mul(i, 16)))), N_MASK)

        let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
        mstore(0x20, leafAdrs)
        mstore(0x40, secretVal)
        let node := and(keccak256(0x00, 0x60), N_MASK)

        let treeAdrsBase := or(shl(128, 3), shl(96, i))
        let pathIdx := treeIdx
        let authBase := add(144, mul(i, 256))

        for { let h := 0 } lt(h, 16) { h := add(h, 1) } {
            let sibling := and(calldataload(add(sigOffset, add(authBase, mul(h, 16)))), N_MASK)
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

    // Last tree (forced-zero): secret = root
    {
        let lastSecret := and(calldataload(add(sigOffset, add(16, mul(7, 16)))), N_MASK)
        mstore(0x20, or(shl(128, 3), shl(96, 7)))
        mstore(0x40, lastSecret)
        mstore(add(0x80, mul(7, 0x20)), and(keccak256(0x00, 0x60), N_MASK))
    }

    // Compress 8 roots
    mstore(0x20, shl(128, 4))
    for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
        mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
    }
    let forsPk := and(keccak256(0x00, 0x140), N_MASK)

    // ---- Hypertree (D=2 layers) ----
    let currentNode := forsPk
    let idxTree := htIdx
    let sigOff := 1936

    for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
        let idxLeaf := and(idxTree, 0xFFF)
        idxTree := shr(12, idxTree)

        let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

        let countOff := add(sigOff, 512)
        let count := shr(224, calldataload(add(sigOffset, countOff)))

        // WOTS digest
        mstore(0x20, wotsAdrs)
        mstore(0x40, currentNode)
        mstore(0x60, count)
        let d := keccak256(0x00, 0x80)

        // Digit sum = 240
        let digitSum := 0
        for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
            digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
        }
        if iszero(eq(digitSum, 240)) { revert(0, 0) }

        // 32 WOTS chains
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let digit := and(shr(mul(i, 4), d), 0xF)
            let steps := sub(15, digit)
            let val := and(calldataload(add(sigOffset, add(sigOff, mul(i, 16)))), N_MASK)
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

        // PK compression
        let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
        mstore(0x20, pkAdrs)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
        }
        let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

        // Merkle auth path (12 levels)
        let authOff := add(countOff, 4)
        let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
        let merkleNode := wotsPk
        let mIdx := idxLeaf

        for { let h := 0 } lt(h, 12) { h := add(h, 1) } {
            let sibling := and(calldataload(add(sigOffset, add(authOff, mul(h, 16)))), N_MASK)
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

    computedRoot := currentNode
}
