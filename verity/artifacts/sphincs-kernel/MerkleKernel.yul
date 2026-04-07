object "MerkleKernel" {
    code {
        if callvalue() {
            revert(0, 0)
        }
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
                    case 0xf3aae285 {
                        /* configureRoot() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 36) {
                            revert(0, 0)
                        }
                        let newRoot := calldataload(4)
                        sstore(0, newRoot)
                        stop()
                    }
                    case 0xfdab463d {
                        /* currentRoot() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 4) {
                            revert(0, 0)
                        }
                        let stored := sload(0)
                        mstore(0, stored)
                        return(0, 32)
                    }
                    case 0x85b39720 {
                        /* previewPath() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        let leaf := calldataload(4)
                        let sibling0 := calldataload(36)
                        let sibling1 := calldataload(68)
                        let sibling2 := calldataload(100)
                        let sibling3 := calldataload(132)
                        let sibling0OnLeft := iszero(iszero(calldataload(164)))
                        let sibling1OnLeft := iszero(iszero(calldataload(196)))
                        let sibling2OnLeft := iszero(iszero(calldataload(228)))
                        let sibling3OnLeft := iszero(iszero(calldataload(260)))
                        let level0 := 0
                        {
                            let __ite_cond := sibling0OnLeft
                            if __ite_cond {
                                level0 := add(mul(sibling0, 65537), add(mul(leaf, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level0 := add(mul(leaf, 65537), add(mul(sibling0, 257), 97))
                            }
                        }
                        let level1 := 0
                        {
                            let __ite_cond := sibling1OnLeft
                            if __ite_cond {
                                level1 := add(mul(sibling1, 65537), add(mul(level0, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level1 := add(mul(level0, 65537), add(mul(sibling1, 257), 97))
                            }
                        }
                        let level2 := 0
                        {
                            let __ite_cond := sibling2OnLeft
                            if __ite_cond {
                                level2 := add(mul(sibling2, 65537), add(mul(level1, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level2 := add(mul(level1, 65537), add(mul(sibling2, 257), 97))
                            }
                        }
                        let level3 := 0
                        {
                            let __ite_cond := sibling3OnLeft
                            if __ite_cond {
                                level3 := add(mul(sibling3, 65537), add(mul(level2, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level3 := add(mul(level2, 65537), add(mul(sibling3, 257), 97))
                            }
                        }
                        mstore(0, level3)
                        return(0, 32)
                    }
                    case 0x64cf5e33 {
                        /* previewPackedPath() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 196) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 196) {
                            revert(0, 0)
                        }
                        let leaf := calldataload(4)
                        let sibling0 := calldataload(36)
                        let sibling1 := calldataload(68)
                        let sibling2 := calldataload(100)
                        let sibling3 := calldataload(132)
                        let directions := calldataload(164)
                        let sibling0OnLeft := iszero(eq(and(directions, 1), 0))
                        let sibling1OnLeft := iszero(eq(and(shr(1, directions), 1), 0))
                        let sibling2OnLeft := iszero(eq(and(shr(2, directions), 1), 0))
                        let sibling3OnLeft := iszero(eq(and(shr(3, directions), 1), 0))
                        let level0 := 0
                        {
                            let __ite_cond := sibling0OnLeft
                            if __ite_cond {
                                level0 := add(mul(sibling0, 65537), add(mul(leaf, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level0 := add(mul(leaf, 65537), add(mul(sibling0, 257), 97))
                            }
                        }
                        let level1 := 0
                        {
                            let __ite_cond := sibling1OnLeft
                            if __ite_cond {
                                level1 := add(mul(sibling1, 65537), add(mul(level0, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level1 := add(mul(level0, 65537), add(mul(sibling1, 257), 97))
                            }
                        }
                        let level2 := 0
                        {
                            let __ite_cond := sibling2OnLeft
                            if __ite_cond {
                                level2 := add(mul(sibling2, 65537), add(mul(level1, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level2 := add(mul(level1, 65537), add(mul(sibling2, 257), 97))
                            }
                        }
                        let level3 := 0
                        {
                            let __ite_cond := sibling3OnLeft
                            if __ite_cond {
                                level3 := add(mul(sibling3, 65537), add(mul(level2, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level3 := add(mul(level2, 65537), add(mul(sibling3, 257), 97))
                            }
                        }
                        mstore(0, level3)
                        return(0, 32)
                    }
                    case 0x5bd839a5 {
                        /* verifyPath() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 292) {
                            revert(0, 0)
                        }
                        let leaf := calldataload(4)
                        let sibling0 := calldataload(36)
                        let sibling1 := calldataload(68)
                        let sibling2 := calldataload(100)
                        let sibling3 := calldataload(132)
                        let sibling0OnLeft := iszero(iszero(calldataload(164)))
                        let sibling1OnLeft := iszero(iszero(calldataload(196)))
                        let sibling2OnLeft := iszero(iszero(calldataload(228)))
                        let sibling3OnLeft := iszero(iszero(calldataload(260)))
                        let stored := sload(0)
                        let level0 := 0
                        {
                            let __ite_cond := sibling0OnLeft
                            if __ite_cond {
                                level0 := add(mul(sibling0, 65537), add(mul(leaf, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level0 := add(mul(leaf, 65537), add(mul(sibling0, 257), 97))
                            }
                        }
                        let level1 := 0
                        {
                            let __ite_cond := sibling1OnLeft
                            if __ite_cond {
                                level1 := add(mul(sibling1, 65537), add(mul(level0, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level1 := add(mul(level0, 65537), add(mul(sibling1, 257), 97))
                            }
                        }
                        let level2 := 0
                        {
                            let __ite_cond := sibling2OnLeft
                            if __ite_cond {
                                level2 := add(mul(sibling2, 65537), add(mul(level1, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                level2 := add(mul(level1, 65537), add(mul(sibling2, 257), 97))
                            }
                        }
                        let candidate := 0
                        {
                            let __ite_cond := sibling3OnLeft
                            if __ite_cond {
                                candidate := add(mul(sibling3, 65537), add(mul(level2, 257), 97))
                            }
                            if iszero(__ite_cond) {
                                candidate := add(mul(level2, 65537), add(mul(sibling3, 257), 97))
                            }
                        }
                        mstore(0, eq(candidate, stored))
                        return(0, 32)
                    }
                    case 0x53e3f484 {
                        /* verifyPackedPath() */
                        if callvalue() {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 196) {
                            revert(0, 0)
                        }
                        if lt(calldatasize(), 196) {
                            revert(0, 0)
                        }
                        let leaf := calldataload(4)
                        let sibling0 := calldataload(36)
                        let sibling1 := calldataload(68)
                        let sibling2 := calldataload(100)
                        let sibling3 := calldataload(132)
                        let directions := calldataload(164)
                        let stored := sload(0)
                        {
                            let __ite_cond := iszero(eq(shr(4, directions), 0))
                            if __ite_cond {
                                mstore(0, 0)
                                return(0, 32)
                            }
                            if iszero(__ite_cond) {
                                let sibling0OnLeft := iszero(eq(and(directions, 1), 0))
                                let sibling1OnLeft := iszero(eq(and(shr(1, directions), 1), 0))
                                let sibling2OnLeft := iszero(eq(and(shr(2, directions), 1), 0))
                                let sibling3OnLeft := iszero(eq(and(shr(3, directions), 1), 0))
                                let level0 := 0
                                {
                                    let __ite_cond := sibling0OnLeft
                                    if __ite_cond {
                                        level0 := add(mul(sibling0, 65537), add(mul(leaf, 257), 97))
                                    }
                                    if iszero(__ite_cond) {
                                        level0 := add(mul(leaf, 65537), add(mul(sibling0, 257), 97))
                                    }
                                }
                                let level1 := 0
                                {
                                    let __ite_cond := sibling1OnLeft
                                    if __ite_cond {
                                        level1 := add(mul(sibling1, 65537), add(mul(level0, 257), 97))
                                    }
                                    if iszero(__ite_cond) {
                                        level1 := add(mul(level0, 65537), add(mul(sibling1, 257), 97))
                                    }
                                }
                                let level2 := 0
                                {
                                    let __ite_cond := sibling2OnLeft
                                    if __ite_cond {
                                        level2 := add(mul(sibling2, 65537), add(mul(level1, 257), 97))
                                    }
                                    if iszero(__ite_cond) {
                                        level2 := add(mul(level1, 65537), add(mul(sibling2, 257), 97))
                                    }
                                }
                                let candidate := 0
                                {
                                    let __ite_cond := sibling3OnLeft
                                    if __ite_cond {
                                        candidate := add(mul(sibling3, 65537), add(mul(level2, 257), 97))
                                    }
                                    if iszero(__ite_cond) {
                                        candidate := add(mul(level2, 65537), add(mul(sibling3, 257), 97))
                                    }
                                }
                                mstore(0, eq(candidate, stored))
                                return(0, 32)
                            }
                        }
                    }
                    default {
                        revert(0, 0)
                    }
                }
            }
        }
    }
}