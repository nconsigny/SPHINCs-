object "SphincsC6Full" {
    code {
        if callvalue() {
            revert(0, 0)
        }
        function internal_chainHash(adrs, val, startPos, steps) -> __ret0 {
            let result := val
            let pos := startPos
            for {
                let step := 0
            } lt(step, steps) {
                step := add(step, 1)
            } {
                let curAdrs := or(and(adrs, 115792089237316195423570985008687907853269984665640564039439137263843715055615), shl(32, pos))
                mstore(32, curAdrs)
                mstore(64, result)
                result := and(keccak256(0, 96), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                pos := add(pos, 1)
            }
            __ret0 := result
            leave
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
            function internal_chainHash(adrs, val, startPos, steps) -> __ret0 {
                let result := val
                let pos := startPos
                for {
                    let step := 0
                } lt(step, steps) {
                    step := add(step, 1)
                } {
                    let curAdrs := or(and(adrs, 115792089237316195423570985008687907853269984665640564039439137263843715055615), shl(32, pos))
                    mstore(32, curAdrs)
                    mstore(64, result)
                    result := and(keccak256(0, 96), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                    pos := add(pos, 1)
                }
                __ret0 := result
                leave
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
                        let sigBase := 100
                        mstore(0, seed)
                        let R := and(calldataload(sigBase), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        mstore(32, root)
                        mstore(64, R)
                        mstore(96, message)
                        let digest := keccak256(0, 128)
                        let htIdx := and(shr(128, digest), 16777215)
                        let lastIdx := and(shr(112, digest), 65535)
                        if iszero(eq(lastIdx, 0)) {
                            mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                            mstore(4, 32)
                            mstore(36, 27)
                            mstore(68, 0x464f52532b4320666f726365642d7a65726f2076696f6c617465640000000000)
                            revert(0, 100)
                        }
                        for {
                            let fi := 0
                        } lt(fi, 7) {
                            fi := add(fi, 1)
                        } {
                            let treeIdx := and(shr(mul(fi, 16), digest), 65535)
                            let secretVal := and(calldataload(add(sigBase, add(16, mul(fi, 16)))), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                            let leafAdrs := or(shl(128, 3), or(shl(96, fi), treeIdx))
                            mstore(32, leafAdrs)
                            mstore(64, secretVal)
                            let node := and(keccak256(0, 96), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                            let treeAdrsBase := or(shl(128, 3), shl(96, fi))
                            let pathIdx := treeIdx
                            let authBase := add(sigBase, add(144, mul(fi, 256)))
                            for {
                                let ah := 0
                            } lt(ah, 16) {
                                ah := add(ah, 1)
                            } {
                                let sibling := and(calldataload(add(authBase, mul(ah, 16))), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let parentIdx := shr(1, pathIdx)
                                mstore(32, or(treeAdrsBase, or(shl(32, add(ah, 1)), parentIdx)))
                                let bit := and(pathIdx, 1)
                                mstore(64, xor(node, mul(xor(node, sibling), bit)))
                                mstore(96, xor(sibling, mul(xor(sibling, node), bit)))
                                node := and(keccak256(0, 128), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                pathIdx := parentIdx
                            }
                            mstore(add(128, mul(fi, 32)), node)
                        }
                        let lastSecret := and(calldataload(add(sigBase, add(16, mul(7, 16)))), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        mstore(32, or(shl(128, 3), shl(96, 7)))
                        mstore(64, lastSecret)
                        mstore(add(128, mul(7, 32)), and(keccak256(0, 96), 115792089237316195423570985008687907852929702298719625575994209400481361428480))
                        mstore(32, shl(128, 4))
                        for {
                            let ri := 0
                        } lt(ri, 8) {
                            ri := add(ri, 1)
                        } {
                            mstore(add(64, mul(ri, 32)), mload(add(128, mul(ri, 32))))
                        }
                        let currentNode := and(keccak256(0, 320), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        let idxTree := htIdx
                        let sigOff := 1936
                        for {
                            let layer := 0
                        } lt(layer, 2) {
                            layer := add(layer, 1)
                        } {
                            let idxLeaf := and(idxTree, 4095)
                            idxTree := shr(12, idxTree)
                            let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                            let countOff := add(sigOff, 512)
                            let count := shr(224, calldataload(add(sigBase, countOff)))
                            mstore(32, wotsAdrs)
                            mstore(64, currentNode)
                            mstore(96, count)
                            let d := keccak256(0, 128)
                            let digitSum := 0
                            for {
                                let di := 0
                            } lt(di, 32) {
                                di := add(di, 1)
                            } {
                                digitSum := add(digitSum, and(shr(mul(di, 4), d), 15))
                            }
                            if iszero(eq(digitSum, 240)) {
                                mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                                mstore(4, 32)
                                mstore(36, 19)
                                mstore(68, 0x574f54532b432073756d2076696f6c6174656400000000000000000000000000)
                                revert(0, 100)
                            }
                            for {
                                let ci := 0
                            } lt(ci, 32) {
                                ci := add(ci, 1)
                            } {
                                let digit := and(shr(mul(ci, 4), d), 15)
                                let steps := sub(15, digit)
                                let val := and(calldataload(add(sigBase, add(sigOff, mul(ci, 16)))), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let chainAdrs := or(wotsAdrs, shl(64, ci))
                                mstore(0, seed)
                                let chainResult := internal_chainHash(chainAdrs, val, digit, steps)
                                mstore(add(128, mul(ci, 32)), chainResult)
                            }
                            let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                            mstore(0, seed)
                            mstore(32, pkAdrs)
                            for {
                                let pi := 0
                            } lt(pi, 32) {
                                pi := add(pi, 1)
                            } {
                                mstore(add(64, mul(pi, 32)), mload(add(128, mul(pi, 32))))
                            }
                            let wotsPk := and(keccak256(0, 1088), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                            let authOff := add(countOff, 4)
                            let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                            let merkleNode := wotsPk
                            let mIdx := idxLeaf
                            for {
                                let mh := 0
                            } lt(mh, 12) {
                                mh := add(mh, 1)
                            } {
                                let mSibling := and(calldataload(add(sigBase, add(authOff, mul(mh, 16)))), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                let mParent := shr(1, mIdx)
                                mstore(32, or(and(treeAdrs, 115792089237316195423570985008687907853269984665640564039439137263839420088320), or(shl(32, add(mh, 1)), mParent)))
                                let mBit := and(mIdx, 1)
                                mstore(64, xor(merkleNode, mul(xor(merkleNode, mSibling), mBit)))
                                mstore(96, xor(mSibling, mul(xor(mSibling, merkleNode), mBit)))
                                merkleNode := and(keccak256(0, 128), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                                mIdx := mParent
                            }
                            currentNode := merkleNode
                            sigOff := add(authOff, mul(12, 16))
                        }
                        mstore(0, eq(currentNode, root))
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