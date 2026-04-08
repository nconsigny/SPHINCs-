// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsC6Asm — Stateless SPHINCS+ C6 verifier (shared, Yul-optimized)
/// @notice Deployed once, used by all accounts. No storage — pure function.
///         Public keys are passed by the caller (the account contract).
/// @dev C6: h=24, d=2, a=16, k=8, w=16, l=32, target_sum=240, sig_size=3352
///      Domain-separated H_msg (160 bytes).
///      Solady-style micro-optimizations: shl for power-of-2 mul, hoisted invariants.
contract SphincsC6Asm {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 3352)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            mstore(0x00, seed)

            // H_msg (domain-separated, 160 bytes)
            let R := and(calldataload(sig.offset), N_MASK)
            mstore(0x20, root)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let digest := keccak256(0x00, 0xA0)

            let htIdx := and(shr(128, digest), 0xFFFFFF)

            // FORS+C (K=8, A=16)
            let dVal := digest
            if and(shr(112, dVal), 0xFFFF) { revert(0, 0) }

            let sigBase := sig.offset
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                let treeIdx := and(shr(shl(4, i), dVal), 0xFFFF)  // shl(4,i) = i*16
                let secretVal := and(calldataload(add(sigBase, add(16, shl(4, i)))), N_MASK)
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx
                // Hoist invariant: authPtr = sigBase + 144 + i*256
                let authPtr := add(sigBase, add(144, shl(8, i)))  // shl(8,i) = i*256

                for { let h := 0 } lt(h, 16) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)  // shl(4,h) = h*16
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    let bit := and(pathIdx, 1)
                    mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)  // shl(5,i) = i*32
            }

            // Last tree (forced-zero): secret = root hash
            {
                let lastSecret := and(calldataload(add(sigBase, 128)), N_MASK)  // 16 + 7*16 = 128
                mstore(0x20, or(shl(128, 3), shl(96, 7)))
                mstore(0x40, lastSecret)
                mstore(0x160, and(keccak256(0x00, 0x60), N_MASK))  // 0x80 + 7*0x20 = 0x160
            }

            // Compress 8 FORS roots
            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x140), N_MASK)

            // Hypertree (D=2)
            let currentNode := forsPk
            let idxTree := htIdx
            let sigOff := 1936

            for { let layer := 0 } lt(layer, 2) { layer := add(layer, 1) } {
                let idxLeaf := and(idxTree, 0xFFF)
                idxTree := shr(12, idxTree)

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                let countOff := add(sigOff, 512)
                let count := shr(224, calldataload(add(sigBase, countOff)))

                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Digit sum check
                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(shl(2, ii), d), 0xF))  // shl(2,ii) = ii*4
                }
                if iszero(eq(digitSum, 240)) { revert(0, 0) }

                // 32 WOTS chains
                // Hoist: wotsPtr = sigBase + sigOff
                let wotsPtr := add(sigBase, sigOff)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let digit := and(shr(shl(2, i), d), 0xF)  // shl(2,i) = i*4
                    let steps := sub(15, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)  // shl(4,i) = i*16
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
                    mstore(add(0x80, shl(5, i)), val)  // shl(5,i) = i*32
                }

                // PK compression
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

                // Merkle auth path (12 levels)
                let authOff := add(countOff, 4)
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                // Hoist: merklePtr = sigBase + authOff
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 12) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)  // shl(4,h) = h*16
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
                sigOff := add(authOff, 192)  // 12*16 = 192
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
