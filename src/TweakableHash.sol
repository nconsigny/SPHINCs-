// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title TweakableHash - Core tweakable hash primitives for SPHINCS+ variants
/// @notice Implements Th(P, T, M) using keccak256 for EVM-native gas efficiency
/// @dev All hash calls are position-bound via ADRS tweaks to prevent multi-target attacks.
///      n = 128 bits (16 bytes) throughout. We store n-bit values in bytes32 with
///      the meaningful 128 bits in the most-significant half (left-aligned).
///      ADRS layout (32 bytes):
///        [0..3]   layer address
///        [4..11]  tree address
///        [12..15] type field (0=WOTS, 1=WOTS_PK, 2=TREE, 3=FORS_TREE, 4=FORS_ROOTS, 5=PORS)
///        [16..19] key pair address
///        [20..23] chain index / tree index
///        [24..27] chain position / node height
///        [28..31] hash address / node index
library TweakableHash {
    // ADRS type constants
    uint32 constant ADRS_WOTS      = 0;
    uint32 constant ADRS_WOTS_PK   = 1;
    uint32 constant ADRS_TREE      = 2;
    uint32 constant ADRS_FORS_TREE = 3;
    uint32 constant ADRS_FORS_ROOTS = 4;
    uint32 constant ADRS_PORS      = 5;

    /// @notice Core tweakable hash: Th(seed, adrs, input) -> n-bit output
    /// @dev keccak256(seed || adrs || input), truncated to 128 bits (left-aligned in bytes32)
    function th(bytes32 seed, bytes32 adrs, bytes32 input) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), adrs)
            mstore(add(m, 0x40), input)
            result := and(keccak256(m, 0x60), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        }
    }

    /// @notice Tweakable hash for two inputs: Th(seed, adrs, left || right)
    /// @dev Used for Merkle tree internal node computation
    function thPair(bytes32 seed, bytes32 adrs, bytes32 left, bytes32 right) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), adrs)
            mstore(add(m, 0x40), left)
            mstore(add(m, 0x60), right)
            result := and(keccak256(m, 0x80), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        }
    }

    /// @notice Tweakable hash for variable-length input (used for PK compression)
    /// @dev keccak256(seed || adrs || data...)
    function thMulti(bytes32 seed, bytes32 adrs, bytes32[] memory inputs) internal pure returns (bytes32 result) {
        uint256 count = inputs.length;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), adrs)
            let ptr := add(m, 0x40)
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                mstore(add(ptr, mul(i, 0x20)), mload(add(add(inputs, 0x20), mul(i, 0x20))))
            }
            let totalLen := add(0x40, mul(count, 0x20))
            result := and(keccak256(m, totalLen), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        }
    }

    /// @notice Message hash: H_msg(seed, root, R, message, chainId, address) for digest generation
    /// @dev Produces a full 256-bit hash used for extracting FORS/PORS indices + hypertree index
    ///      Includes chainId and contract address to prevent cross-chain replay attacks
    function hMsg(
        bytes32 seed,
        bytes32 root,
        bytes32 R,
        bytes32 message
    ) internal view returns (bytes32 digest) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), root)
            mstore(add(m, 0x40), R)
            mstore(add(m, 0x60), message)
            mstore(add(m, 0x80), chainid())
            mstore(add(m, 0xA0), address())
            digest := keccak256(m, 0xC0)
        }
    }

    /// @notice WOTS+C chain hash step with incremental ADRS updates
    /// @dev Completes chain from startPos to startPos+steps, each step hashing with unique tweak
    /// @param seed PK.seed
    /// @param adrs ADRS with layer/tree/keypair already set; chain index in [20..23]
    /// @param input Starting chain value sigma_i
    /// @param startPos Starting position a_i in chain
    /// @param steps Number of steps (w - 1 - a_i)
    function chainHash(
        bytes32 seed,
        bytes32 adrs,
        bytes32 input,
        uint256 startPos,
        uint256 steps
    ) internal pure returns (bytes32 result) {
        result = input;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            // We modify adrs in-place for chain position
            let adrsWord := adrs
            let ptr := add(m, 0x20)

            for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                // Set chain position = startPos + step in ADRS bytes [24..27]
                let pos := add(startPos, step)
                // Clear bytes [24..27] and set new position
                adrsWord := or(
                    and(adrsWord, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                    shl(32, and(pos, 0xFFFFFFFF))
                )
                mstore(ptr, adrsWord)
                mstore(add(m, 0x40), result)
                result := and(keccak256(m, 0x60), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
            }
        }
    }

    /// @notice Build ADRS word from components
    function makeAdrs(
        uint32 layer,
        uint64 treeAddr,
        uint32 adrsType,
        uint32 keyPair,
        uint32 chainOrTreeIdx,
        uint32 chainPosOrHeight,
        uint32 hashAddr
    ) internal pure returns (bytes32 adrs) {
        assembly ("memory-safe") {
            adrs := or(shl(224, layer), or(shl(160, treeAddr), or(shl(128, adrsType),
                or(shl(96, keyPair), or(shl(64, chainOrTreeIdx),
                or(shl(32, chainPosOrHeight), hashAddr))))))
        }
    }

    /// @notice Set chain index in ADRS bytes [20..23]
    function setChainIndex(bytes32 adrs, uint32 idx) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            adrs := or(
                and(adrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF),
                shl(64, and(idx, 0xFFFFFFFF))
            )
        }
        return adrs;
    }

    /// @notice Set key pair address in ADRS bytes [16..19]
    function setKeyPair(bytes32 adrs, uint32 kp) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            adrs := or(
                and(adrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFF),
                shl(96, and(kp, 0xFFFFFFFF))
            )
        }
        return adrs;
    }

    /// @notice Set type field in ADRS bytes [12..15]
    function setType(bytes32 adrs, uint32 t) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            // Clear bytes [12..31] (160 bits) and set type in [12..15]
            // Keep top 96 bits (bytes 0..11), clear remaining 160 bits
            adrs := or(
                and(adrs, 0xFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000),
                shl(128, and(t, 0xFFFFFFFF))
            )
        }
        return adrs;
    }

    /// @notice Set tree height in ADRS bytes [24..27]
    function setTreeHeight(bytes32 adrs, uint32 h) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            adrs := or(
                and(adrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                shl(32, and(h, 0xFFFFFFFF))
            )
        }
        return adrs;
    }

    /// @notice Set tree/node index in ADRS bytes [28..31]
    function setTreeIndex(bytes32 adrs, uint32 idx) internal pure returns (bytes32) {
        assembly ("memory-safe") {
            adrs := or(
                and(adrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000),
                and(idx, 0xFFFFFFFF)
            )
        }
        return adrs;
    }

    /// @notice Walk a standard Merkle authentication path from leaf to root
    /// @param seed PK.seed
    /// @param adrs Base ADRS (type=TREE)
    /// @param leaf The leaf hash
    /// @param authPath Array of sibling hashes
    /// @param leafIndex Index of the leaf
    /// @return root The computed root hash
    function merkleAuthPath(
        bytes32 seed,
        bytes32 adrs,
        bytes32 leaf,
        bytes32[] memory authPath,
        uint256 leafIndex
    ) internal pure returns (bytes32 root) {
        root = leaf;
        uint256 idx = leafIndex;
        for (uint256 i = 0; i < authPath.length; i++) {
            // Update ADRS: height = i+1, index = idx/2
            adrs = setTreeHeight(adrs, uint32(i + 1));
            adrs = setTreeIndex(adrs, uint32(idx >> 1));

            // Branchless left/right ordering
            bytes32 left;
            bytes32 right;
            assembly ("memory-safe") {
                let bit := and(idx, 1)
                let sibling := mload(add(add(authPath, 0x20), mul(i, 0x20)))
                left := xor(root, mul(xor(root, sibling), bit))
                right := xor(sibling, mul(xor(sibling, root), bit))
            }
            root = thPair(seed, adrs, left, right);
            idx = idx >> 1;
        }
    }
}
