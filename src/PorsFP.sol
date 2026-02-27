// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TweakableHash} from "./TweakableHash.sol";

/// @title PorsFP - PORS+FP verification with Octopus-compressed authentication sets
/// @notice Implements PORS with Forced Pruning from ePrint 2025/2203 and 2025/2069:
///         Instead of k separate FORS trees, uses a single large Merkle tree with
///         k*t leaves. The Octopus algorithm computes the minimal auth set for k
///         simultaneously-opened leaves, and grinding ensures |auth set| <= mMax.
/// @dev Used by Contracts 1 and 3 (W+C + P+FP variants)
library PorsFP {
    struct AuthNode {
        uint8 level;      // Tree level of this node (0 = leaf level)
        uint32 index;     // Node index at this level
        bytes32 hash;     // Node hash value
    }

    /// @notice Verify PORS+FP signature with Octopus-compressed auth set
    /// @param seed PK.seed
    /// @param adrs ADRS base
    /// @param digest Full H_msg digest for index extraction
    /// @param secretValues k revealed secret leaf values
    /// @param authSet Octopus-compressed authentication nodes, sorted by (level desc, index asc)
    /// @param k Number of leaves to open
    /// @param treeHeight Height of the single PORS tree (ceil(log2(k * 2^a)))
    /// @param mMax Maximum allowed auth set size
    /// @return porsPk The reconstructed PORS root (= PORS public key)
    function verify(
        bytes32 seed,
        bytes32 adrs,
        bytes32 digest,
        bytes32[] memory secretValues,
        AuthNode[] memory authSet,
        uint256 k,
        uint256 treeHeight,
        uint256 mMax
    ) internal pure returns (bytes32 porsPk) {
        require(secretValues.length == k, "PORS+FP: wrong secret count");
        require(authSet.length <= mMax, "PORS+FP: auth set too large");

        // Extract k distinct sorted indices from digest
        uint256 totalLeaves = 1 << treeHeight;
        uint256[] memory indices = _hashToSubset(digest, k, totalLeaves, treeHeight);

        // Compute leaf hashes
        bytes32[] memory leafHashes = new bytes32[](k);
        for (uint256 i = 0; i < k; i++) {
            bytes32 leafAdrs = TweakableHash.makeAdrs(
                uint32(uint256(adrs) >> 224),
                uint64(uint256(adrs) >> 160),
                TweakableHash.ADRS_PORS,
                0,
                0,                            // height = 0
                0,
                uint32(indices[i])            // leaf index
            );
            leafHashes[i] = TweakableHash.th(seed, leafAdrs, secretValues[i]);
        }

        // Reconstruct root via Octopus algorithm
        porsPk = _reconstructFromOctopus(seed, adrs, indices, leafHashes, authSet, treeHeight);
    }

    /// @notice Hash digest to k distinct sorted indices in [0, totalLeaves)
    /// @dev Extracts candidates from extended hash, rejects out-of-range and duplicates
    function _hashToSubset(
        bytes32 digest,
        uint256 k,
        uint256 totalLeaves,
        uint256 treeHeight
    ) private pure returns (uint256[] memory indices) {
        indices = new uint256[](k);
        uint256 count = 0;
        uint256 nonce = 0;

        // Use bitmap for O(k) duplicate detection when totalLeaves is small.
        uint256 bitmapSize = (totalLeaves + 255) >> 8;
        bool useBitmap = bitmapSize <= 256;
        uint256[] memory bitmap;
        if (useBitmap) {
            bitmap = new uint256[](bitmapSize);
        }

        // We may need more bits than a single digest provides
        // Use keccak256(digest || nonce) to extend
        while (count < k) {
            bytes32 extended;
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, digest)
                mstore(add(m, 0x20), nonce)
                extended := keccak256(m, 0x40)
            }

            uint256 bits = uint256(extended);
            uint256 bitsPerIndex = treeHeight;

            for (uint256 b = 0; b + bitsPerIndex <= 256 && count < k; b += bitsPerIndex) {
                uint256 candidate = (bits >> b) & ((1 << bitsPerIndex) - 1);
                if (candidate < totalLeaves) {
                    if (useBitmap) {
                        // Check distinctness using bitmap
                        uint256 wordIdx = candidate >> 8;
                        uint256 bitIdx = candidate & 0xFF;
                        uint256 mask = 1 << bitIdx;

                        if (bitmap[wordIdx] & mask == 0) {
                            bitmap[wordIdx] |= mask;
                            indices[count] = candidate;
                            count++;
                        }
                    } else {
                        // Fallback to O(k^2) duplicate detection to avoid large bitmap allocation.
                        bool dup = false;
                        for (uint256 j = 0; j < count; j++) {
                            if (indices[j] == candidate) {
                                dup = true;
                                break;
                            }
                        }
                        if (!dup) {
                            indices[count] = candidate;
                            count++;
                        }
                    }
                }
            }
            nonce++;
        }

        // Sort indices (insertion sort, k is small)
        for (uint256 i = 1; i < k; i++) {
            uint256 key = indices[i];
            uint256 j = i;
            while (j > 0 && indices[j - 1] > key) {
                indices[j] = indices[j - 1];
                j--;
            }
            indices[j] = key;
        }
    }

    /// @notice Reconstruct Merkle root from k leaves + Octopus auth set
    /// @dev Bottom-up level-by-level reconstruction. At each level, known nodes are
    ///      paired: if both children are known, compute parent directly; otherwise
    ///      fetch sibling from auth set.
    function _reconstructFromOctopus(
        bytes32 seed,
        bytes32 adrs,
        uint256[] memory leafIndices,
        bytes32[] memory leafHashes,
        AuthNode[] memory authSet,
        uint256 treeHeight
    ) private pure returns (bytes32 root) {
        uint256 k = leafIndices.length;
        uint256 authIdx = 0;

        // Working arrays for current level
        uint256 currentCount = k;
        uint256[] memory currentIndices = new uint256[](k + authSet.length);
        bytes32[] memory currentHashes = new bytes32[](k + authSet.length);

        for (uint256 i = 0; i < k; i++) {
            currentIndices[i] = leafIndices[i];
            currentHashes[i] = leafHashes[i];
        }

        // Process level by level, bottom-up
        for (uint256 level = 0; level < treeHeight; level++) {
            uint256 newCount = 0;

            uint256 j = 0;
            while (j < currentCount) {
                uint256 idx = currentIndices[j];
                uint256 sibling = idx ^ 1;
                uint256 parent = idx >> 1;

                // Check if next element is the sibling
                if (j + 1 < currentCount && currentIndices[j + 1] == sibling) {
                    // Both children known
                    bytes32 left;
                    bytes32 right;
                    if (idx < sibling) {
                        left = currentHashes[j];
                        right = currentHashes[j + 1];
                    } else {
                        left = currentHashes[j + 1];
                        right = currentHashes[j];
                    }

                    bytes32 nodeAdrs = TweakableHash.makeAdrs(
                        uint32(uint256(adrs) >> 224),
                        uint64(uint256(adrs) >> 160),
                        TweakableHash.ADRS_TREE,
                        0, 0,
                        uint32(level + 1),
                        uint32(parent)
                    );
                    currentHashes[newCount] = TweakableHash.thPair(seed, nodeAdrs, left, right);
                    currentIndices[newCount] = parent;
                    newCount++;
                    j += 2;
                } else {
                    // Need sibling from auth set
                    require(authIdx < authSet.length, "PORS+FP: auth set exhausted");
                    require(
                        authSet[authIdx].level == uint8(level) &&
                        authSet[authIdx].index == uint32(sibling),
                        "PORS+FP: auth set mismatch"
                    );
                    bytes32 siblingHash = authSet[authIdx].hash;
                    authIdx++;

                    bytes32 left;
                    bytes32 right;
                    if (idx & 1 == 0) {
                        left = currentHashes[j];
                        right = siblingHash;
                    } else {
                        left = siblingHash;
                        right = currentHashes[j];
                    }

                    bytes32 nodeAdrs = TweakableHash.makeAdrs(
                        uint32(uint256(adrs) >> 224),
                        uint64(uint256(adrs) >> 160),
                        TweakableHash.ADRS_TREE,
                        0, 0,
                        uint32(level + 1),
                        uint32(parent)
                    );
                    currentHashes[newCount] = TweakableHash.thPair(seed, nodeAdrs, left, right);
                    currentIndices[newCount] = parent;
                    newCount++;
                    j += 1;
                }
            }
            currentCount = newCount;
        }

        require(currentCount == 1 && currentIndices[0] == 0, "PORS+FP: root not reached");
        require(authIdx == authSet.length, "PORS+FP: auth set not fully consumed");
        root = currentHashes[0];
    }
}
