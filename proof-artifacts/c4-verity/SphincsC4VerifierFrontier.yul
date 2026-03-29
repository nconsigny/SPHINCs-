object "SphincsC4VerifierFrontier" {
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
        let root := mload(32)
        let arg0 := seed
        let arg1 := root
        sstore(0, seed)
        sstore(1, root)
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
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
                        let sigLenAnchor := 68
                        let sigBaseAnchor := 100
                        let inputLen := 128
                        let sigLen := calldataload(68)
                        if iszero(eq(sigLen, 3740)) {
                            mstore(0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                            mstore(4, 32)
                            mstore(36, 18)
                            mstore(68, 0x496e76616c696420736967206c656e6774680000000000000000000000000000)
                            revert(0, 100)
                        }
                        let rWord := and(calldataload(100), 115792089237316195423570985008687907852929702298719625575994209400481361428480)
                        mstore(0, sload(0))
                        mstore(32, sload(1))
                        mstore(64, rWord)
                        mstore(96, message)
                        let digest := keccak256(0, 128)
                        let htIdx := and(shr(112, digest), 1073741823)
                        mstore(0, 1)
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