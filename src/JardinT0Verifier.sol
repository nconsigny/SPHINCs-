// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinT0Verifier — JARDINERO Tier 0 W+C verifier
/// @dev Parameters T0_W+C_h14_d7_a6_k39:
///      n=16 (128-bit), h=14, d=7, h'=2, a=6, k=39, w=16, l=32, swn=240.
///      Plain FORS (no FORS+C), WOTS+C hypertree, keccak256-truncated-to-128.
///
///      H_msg domain separator: 0xFF..FE (distinct from C11's 0xFF..FF).
///
///      Signature layout (8220 bytes, constant):
///        [ R                16 bytes ]
///        [ FORS secrets     k*n = 624 bytes ]
///        [ FORS auth paths  k*a*n = 3744 bytes ]
///        [ Hypertree        d*(4 + l*n + h'*n) = 7*548 = 3836 bytes ]
///
///      Designed to replace the C11 slot-registration path for JARDÍN
///      accounts: onboarding builds only the top-layer XMSS (4 WOTS+C
///      keypairs), ~40× faster than C11 on hardware.
contract JardinT0Verifier {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 8220)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── H_msg: keccak(seed || root || R || message || 0xFF..FE) = 160B ──
            mstore(0x00, seed)
            mstore(0x20, root)
            let R := and(calldataload(sigBase), N_MASK)
            mstore(0x40, R)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)
            let dVal := keccak256(0x00, 0xA0)

            // FORS uses bits 0..233 of the digest (k*a = 39*6 = 234 bits).
            // htIdx uses the next 14 bits at [234..247].
            let htIdx := and(shr(234, dVal), 0x3FFF)

            // seed is at mem[0x00] throughout — keep it there.
            mstore(0x00, seed)

            // ── FORS (plain, k=39 trees of height a=6) ──
            // secret_t at: sig + 0x10 + t*0x10
            // auth_t at:   sig + 0x280 + t*0x60 (each path = a*n = 96 bytes)
            // Store root_t at: mem[0x80 + t*0x20] during loop; compress at end.
            for { let t := 0 } lt(t, 39) { t := add(t, 1) } {
                let leafIdx := and(shr(mul(t, 6), dVal), 0x3F)
                let secret  := and(calldataload(add(sigBase, add(0x10, shl(4, t)))), N_MASK)

                // Leaf adrs: (type=FORS_TREE=3, kp=t, y=leafIdx)
                let treeAdrsBase := or(shl(128, 3), shl(96, t))
                mstore(0x20, or(treeAdrsBase, leafIdx))
                mstore(0x40, secret)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := leafIdx
                // auth path pointer for this tree
                let authPtr := add(sigBase, add(0x280, mul(t, 96)))

                for { let h := 0 } lt(h, 6) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // Parent adrs: x = h+1, y = parentIdx
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, t)), node)
            }

            // ── Compress 39 FORS roots → forsPk ──
            // keccak(seed || FORS_ROOTS adrs || root_0 || ... || root_38)
            // total = 32 + 32 + 39*32 = 1312 = 0x520
            mstore(0x20, shl(128, 4)) // FORS_ROOTS adrs, all other fields 0
            for { let t := 0 } lt(t, 39) { t := add(t, 1) } {
                mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
            }
            let forsPk := and(keccak256(0x00, 0x520), N_MASK)

            // ── Hypertree (d=7, h'=2, w=16, l=32, swn=240) ──
            let currentNode := forsPk
            let idx := htIdx
            // HT_OFFSET in sig = R(16) + K*N(624) + K*A*N(3744) = 4384 = 0x1120
            let sigOff := 0x1120

            for { let layer := 0 } lt(layer, 7) { layer := add(layer, 1) } {
                let idxLeaf := and(idx, 3)    // h'=2 ⇒ 2 bits
                let idxTree := shr(2, idx)
                idx := idxTree

                let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
                // counter at sigOff, 4 bytes; read as low 4 bytes of word
                let countOff := sigOff
                let count := shr(224, calldataload(add(sigBase, countOff)))

                // WOTS+C digest: keccak(seed || wotsAdrs || currentNode || count) = 128B
                mstore(0x20, wotsAdrs)
                mstore(0x40, currentNode)
                mstore(0x60, count)
                let d := keccak256(0x00, 0x80)

                // Validate digit sum = 240 (32 base-16 digits, 4 bits each)
                let digitSum := 0
                for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                    digitSum := add(digitSum, and(shr(shl(2, ii), d), 0xF))
                }
                if iszero(eq(digitSum, 240)) { revert(0, 0) }

                // 32 WOTS chains: chain_i walks from digit_i to w-1=15 (max 15 steps)
                let wotsPtr := add(sigBase, add(sigOff, 4))
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    let digit := and(shr(shl(2, i), d), 0xF)
                    let steps := sub(15, digit)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    // chainBase: wotsAdrs with ci=i, x=0 (cleared)
                    let chainBase := and(
                        or(wotsAdrs, shl(64, i)),
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF
                    )

                    for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                        mstore(0x20, or(chainBase, shl(32, add(digit, step))))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // WOTS PK compression: keccak(seed || pkAdrs || chain_0 || ... || chain_31)
                // total = 32 + 32 + 32*32 = 1088 = 0x440
                let pkAdrs := or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf))))
                mstore(0x20, pkAdrs)
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                }
                let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

                // Merkle auth path (h'=2 levels)
                let authOff := add(countOff, add(4, shl(9, 1))) // countOff + 4 + L*N = +4 + 512
                let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
                let merkleNode := wotsPk
                let mIdx := idxLeaf
                let merklePtr := add(sigBase, authOff)

                for { let h := 0 } lt(h, 2) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(
                        and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                        or(shl(32, add(h, 1)), parentIdx)
                    ))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff := add(sigOff, 548) // 4 + L*N + H'*N = 4 + 512 + 32
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
