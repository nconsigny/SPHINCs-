// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsC6Asm — Stateless SPHINCS+ C6 verifier (shared, Yul-optimized)
/// @notice Deployed once, used by all accounts. No storage — pure function.
///         Public keys are passed by the caller (the account contract).
///         Follows the ZKnox/Kohaku shared verifier pattern.
/// @dev C6: h=24, d=2, a=16, k=8, w=16, l=32, target_sum=240, sig_size=3352
///      Domain-separated H_msg (160 bytes).
contract SphincsC6Asm {

    /// @notice Verify a SPHINCS+ C6 signature
    /// @param pkSeed The signer's public seed (128-bit, left-aligned)
    /// @param pkRoot The signer's Merkle root (128-bit, left-aligned)
    /// @param message The signed message hash
    /// @param sig The SPHINCS+ signature (3352 bytes)
    /// @return valid True if signature is valid for the given keys
    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // Verify sig length = 3352
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
            let lastIdx := and(shr(112, dVal), 0xFFFF)
            if lastIdx { revert(0, 0) }

            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 16), dVal), 0xFFFF)
                let secretVal := and(calldataload(add(sig.offset, add(16, mul(i, 16)))), N_MASK)
                let leafAdrs := or(shl(128, 3), or(shl(96, i), treeIdx))
                mstore(0x20, leafAdrs)
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx
                let authBase := add(144, mul(i, 256))

                for { let h := 0 } lt(h, 16) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(sig.offset, add(authBase, mul(h, 16)))), N_MASK)
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

            {
                let lastSecret := and(calldataload(add(sig.offset, add(16, mul(7, 16)))), N_MASK)
                mstore(0x20, or(shl(128, 3), shl(96, 7)))
                mstore(0x40, lastSecret)
                mstore(add(0x80, mul(7, 0x20)), and(keccak256(0x00, 0x60), N_MASK))
            }

            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
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
                let count := shr(224, calldataload(add(sig.offset, countOff)))

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
                    let val := and(calldataload(add(sig.offset, add(sigOff, mul(i, 16)))), N_MASK)
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

                for { let h := 0 } lt(h, 12) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(sig.offset, add(authOff, mul(h, 16)))), N_MASK)
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

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
