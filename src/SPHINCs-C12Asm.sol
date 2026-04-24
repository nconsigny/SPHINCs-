// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SPHINCs-C12Asm — plain SPHINCS+ (SPX) verifier, JARDIN 32-byte ADRS
/// @dev The C12 variant of the SPHINCs- family.  Unlike C6..C11 (which use the
///      WOTS+C / FORS+C compact constructions), C12 is plain SPHINCS+ with
///      standard WOTS+ checksum and standard FORS — a hypertree of depth
///      d=5, per-layer XMSS height h'=4.
///
///      Parameters: n=16, h=20, d=5, h'=4, a=7, k=20, w=8, l=45.
///      6,512 B signature, ~36.6K keccak calls to sign, ~276K verify.
///
///      Matches the JARDIN family byte layout end-to-end: 32-byte ADRS,
///      seed‖adrs‖args keccak inputs, LSB-first digest parsing — so a device
///      port shares one tweakable-hash kernel with C7 / C11 and with the
///      SLH-DSA-Keccak-128-24 verifier in this repo.
///
///      Hash primitives (all keccak256 truncated to 16B):
///        F     : keccak(seed32 ‖ adrs32 ‖ M32)                      96 B
///        H     : keccak(seed32 ‖ adrs32 ‖ L32 ‖ R32)               128 B
///        T_l   : keccak(seed32 ‖ adrs32 ‖ v0..v44  (45 × 32B))    1,504 B
///        T_k   : keccak(seed32 ‖ adrs32 ‖ r0..r19  (20 × 32B))      704 B
///        Hmsg  : keccak(seed32 ‖ root32 ‖ R32 ‖ msg32 ‖ dom32)      160 B
///                where dom = 0xFF..FC (distinct from C11/T0/plain-FORS)
///
///      ADRS (32 bytes, four uint32 words + a uint64 tree word):
///        layer(4) ‖ tree(8) ‖ type(4) ‖ kp(4) ‖ ci(4) ‖ cp(4) ‖ ha(4)
///
///      C12 field mapping:
///        type 0 WOTS_HASH    kp=leaf   ci=chain_i   cp=hash_step   ha=0
///        type 1 WOTS_PK      kp=leaf   ci=0         cp=0           ha=0
///        type 2 XMSS_TREE    kp=0      ci=0         cp=height      ha=parentIdx
///        type 3 FORS_TREE    kp=leaf   ci=0         cp=height      ha=(t<<(A-h))|parent
///        type 4 FORS_ROOTS   kp=leaf   ci=0         cp=0           ha=0
///
///      Signature layout (6,512 bytes, constant):
///        R(32) ‖ FORS(k=20 × (sk 16B + auth 7×16B)) = 2,560
///              ‖ Hypertree(d=5 layers × (WOTS 45×16B + XMSS auth 4×16B)) = 3,920
contract SPHINCs_C12Asm {

    function verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes calldata sig)
        external pure returns (bool valid)
    {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            if iszero(eq(sig.length, 6512)) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── Hmsg: keccak(seed ‖ root ‖ R ‖ msg ‖ dom=0xFF..FC) = 160 B ──
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, calldataload(sigBase))       // R (32 B, full word)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC)
            let dVal := keccak256(0x00, 0xA0)

            // LSB-first digest parsing (JARDIN convention):
            //   md[t] for t in 0..19 : 7 bits at bit t*7
            //   treeIdx              : 16 bits at bit 140
            //   leafIdx              :  4 bits at bit 156
            let treeIdx := and(shr(140, dVal), 0xFFFF)
            let leafIdx := and(shr(156, dVal), 0xF)

            // Put seed back at 0x00 for all subsequent hash calls.
            mstore(0x00, seed)

            // ───────────────────────── FORS ─────────────────────────
            // FORS ADRS base for this signature: type=3, layer=0, tree=treeIdx, kp=leafIdx
            //   = shl(160, treeIdx) | shl(128, 3) | shl(96, leafIdx)
            let forsBase := or(or(shl(160, treeIdx), shl(128, 3)), shl(96, leafIdx))
            let forsOff := 32   // R is 32 bytes

            for { let t := 0 } lt(t, 20) { t := add(t, 1) } {
                let mdT      := and(shr(mul(7, t), dVal), 0x7F)
                let treeOff  := add(forsOff, mul(t, 128))   // 128 = sk(16) + auth(7×16)
                let sk       := and(calldataload(add(sigBase, treeOff)), N_MASK)

                // Leaf ADRS: cp=0, ha = (t << A) | mdT  (global y across 20 trees, A=7)
                mstore(0x20, or(forsBase, or(shl(7, t), mdT)))
                mstore(0x40, sk)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let authPtr := add(sigBase, add(treeOff, 16))
                let pathIdx := mdT
                for { let j := 0 } lt(j, 7) { j := add(j, 1) } {
                    let sibling    := and(calldataload(add(authPtr, shl(4, j))), N_MASK)
                    let parentIdx  := shr(1, pathIdx)
                    // height = j+1;  global y = (t << (A - h)) | parent
                    let globalY := or(shl(sub(6, j), t), parentIdx)
                    mstore(0x20, or(forsBase, or(shl(32, add(j, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x80 + t*0x20
                mstore(add(0x80, shl(5, t)), node)
            }

            // ── Compress 20 FORS roots: T_k(seed, FORS_ROOTS adrs, roots) ──
            // total = seed(32) + adrs(32) + 20*32 = 704 = 0x2C0
            {
                let adrsRoots := or(or(shl(160, treeIdx), shl(128, 4)), shl(96, leafIdx))
                mstore(0x20, adrsRoots)
                // Pack pattern identical to C11/FORS+C: pack[t] at 0x40+t*0x20,
                // storage[t] at 0x80+t*0x20. Safe because pack[t] overwrites
                // storage[t-2] which was already consumed.
                for { let t := 0 } lt(t, 20) { t := add(t, 1) } {
                    mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
                }
            }
            let currentNode := and(keccak256(0x00, 0x2C0), N_MASK)   // fors_pk

            // ───────────────────── Hypertree (d=5 layers) ─────────────────────
            let curTree := treeIdx
            let curLeaf := leafIdx
            let sigOff  := 2592   // R(32) + FORS(2560)

            for { let layer := 0 } lt(layer, 5) { layer := add(layer, 1) } {
                // WOTS+ digits from currentNode (128-bit value in high 16B of word).
                //   msg_digit[i] (i=0..41) = (node >> (128 + 3i)) & 7   — LSB-first
                //   csum = Σ (7 - digit[i])
                //   csum_digit[j] (j=0..2) = (csum_shifted >> (13 - 3j)) & 7  (MSB-first, SLH-DSA)

                // WOTS ADRS base for this layer: type=0, layer, tree=curTree, kp=curLeaf
                let wotsBase := or(or(shl(224, layer), shl(160, curTree)), shl(96, curLeaf))
                let wotsPtr  := add(sigBase, sigOff)

                let csum := 0

                // ── 42 message-digit chains ──
                for { let i := 0 } lt(i, 42) { i := add(i, 1) } {
                    let digit := and(shr(add(128, mul(3, i)), currentNode), 7)
                    csum := add(csum, sub(7, digit))

                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := or(wotsBase, shl(64, i))   // ci=i
                    let steps := sub(7, digit)
                    for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                        // cp = digit + s  (hash step within chain)
                        mstore(0x20, or(chainBase, shl(32, add(digit, s))))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // ── 3 checksum chains (i = 42, 43, 44) ──
                let csumShifted := shl(7, csum)
                for { let j := 0 } lt(j, 3) { j := add(j, 1) } {
                    let digit := and(shr(sub(13, mul(3, j)), csumShifted), 7)
                    let i := add(42, j)
                    let val := and(calldataload(add(wotsPtr, shl(4, i))), N_MASK)
                    let chainBase := or(wotsBase, shl(64, i))
                    let steps := sub(7, digit)
                    for { let s := 0 } lt(s, steps) { s := add(s, 1) } {
                        mstore(0x20, or(chainBase, shl(32, add(digit, s))))
                        mstore(0x40, val)
                        val := and(keccak256(0x00, 0x60), N_MASK)
                    }
                    mstore(add(0x80, shl(5, i)), val)
                }

                // ── WOTS_PK compression via T_l (45 chain outputs) ──
                // total = seed(32) + adrs(32) + 45*32 = 1504 = 0x5E0
                {
                    let pkAdrs := or(or(shl(224, layer), shl(160, curTree)),
                                      or(shl(128, 1), shl(96, curLeaf)))
                    mstore(0x20, pkAdrs)
                    for { let i := 0 } lt(i, 45) { i := add(i, 1) } {
                        mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
                    }
                }
                let wotsPk := and(keccak256(0x00, 0x5E0), N_MASK)

                // ── XMSS auth climb (h' = 4) ──
                let authOff := add(sigOff, 720)   // 45 × 16
                let authPtr := add(sigBase, authOff)
                // XMSS_TREE ADRS base: type=2, layer, tree=curTree, kp=0
                let xmssBase := or(or(shl(224, layer), shl(160, curTree)), shl(128, 2))
                let merkleNode := wotsPk
                let mIdx := curLeaf
                for { let h := 0 } lt(h, 4) { h := add(h, 1) } {
                    let sibling   := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, mIdx)
                    mstore(0x20, or(xmssBase, or(shl(32, add(h, 1)), parentIdx)))
                    let s := shl(5, and(mIdx, 1))
                    mstore(xor(0x40, s), merkleNode)
                    mstore(xor(0x60, s), sibling)
                    merkleNode := and(keccak256(0x00, 0x80), N_MASK)
                    mIdx := parentIdx
                }

                currentNode := merkleNode
                sigOff      := add(authOff, 64)   // + 4 × 16

                // Advance: leaf = tree & 0xF, tree = tree >> 4.
                curLeaf := and(curTree, 0xF)
                curTree := shr(4, curTree)
            }

            valid := eq(currentNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
