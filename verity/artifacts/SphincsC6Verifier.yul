object "SphincsC6Verifier" {
    code {
        if callvalue() {
            revert(0, 0)
        }
        let argsOffset := add(dataoffset("runtime"), datasize("runtime"))
        let argsSize := sub(codesize(), argsOffset)
        codecopy(0, argsOffset, argsSize)
        if lt(argsSize, 64) {
            revert(0, 0)
        }
        let seed := mload(0)
        let pkRoot := mload(32)
        let arg0 := seed
        let arg1 := pkRoot
        sstore(0, arg0)
        sstore(1, arg1)
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            function sphincsC6Verify(sigOffset, message, seed) -> computedRoot {
                let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

                // seed is already in the caller's memory at 0x00
                mstore(0x00, seed)

                // Read pkRoot from storage (needed for H_msg)
                let root := sload(1)

                // H_msg: keccak256(seed || root || R || message)
                let R := and(calldataload(sigOffset), N_MASK)
                mstore(0x20, root)
                mstore(0x40, R)
                mstore(0x60, message)
                let digest := keccak256(0x00, 0x80)

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
            {
                let __has_selector := iszero(lt(calldatasize(), 4))
                if iszero(__has_selector) {
                    revert(0, 0)
                }
                if __has_selector {
                    switch shr(224, calldataload(0))
                    case 0x258ae582 {
                        /* verify() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 68) {
                            revert(0, 0)
                        }
                        let message := calldataload(4)
                        let sig_offset := calldataload(36)
                        if lt(sig_offset, 64) {
                            revert(0, 0)
                        }
                        let sig_abs_offset := add(4, sig_offset)
                        if gt(sig_abs_offset, sub(calldatasize(), 32)) {
                            revert(0, 0)
                        }
                        let sig_length := calldataload(sig_abs_offset)
                        let sig_tail_head_end := add(sig_abs_offset, 32)
                        let sig_tail_remaining := sub(calldatasize(), sig_tail_head_end)
                        if gt(sig_length, sig_tail_remaining) {
                            revert(0, 0)
                        }
                        let sig_data_offset := sig_tail_head_end
                        let seed := sload(0)
                        let root := sload(1)
                        let sigLen := calldataload(68)
                        if iszero(eq(sigLen, 3352)) {
                            mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                            mstore(4, 32)
                            mstore(36, 18)
                            mstore(68, 0x496e76616c696420736967206c656e6774680000000000000000000000000000)
                            revert(0, 100)
                        }
                        let computedRoot := sphincsC6Verify(100, message, seed)
                        let maskedRoot := and(computedRoot, 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        let valid := eq(maskedRoot, root)
                        mstore(0, valid)
                        return(0, 32)
                    }
                    case 0xe2bdbfac {
                        /* pkSeed() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, sload(0))
                        return(0, 32)
                    }
                    case 0x00dfc40a {
                        /* pkRoot() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        mstore(0, sload(1))
                        return(0, 32)
                    }
                    default {
                        revert(0, 0)
                    }
                }
            }
        }
    }
}