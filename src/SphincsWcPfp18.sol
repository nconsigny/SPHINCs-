// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TweakableHash} from "./TweakableHash.sol";
import {WotsPlusC} from "./WotsPlusC.sol";

/// @title SphincsWcPfp18 - Tweaked SPHINCS+ Verifier: W+C + P+FP (h=18, d=2, a=13, k=13)
/// @notice Contract 1: WOTS+C with PORS+FP. Sig: 3480 bytes.
contract SphincsWcPfp18 {
    uint256 constant N = 16;
    uint256 constant H = 18;
    uint256 constant D = 2;
    uint256 constant SUBTREE_H = 9;
    uint256 constant A = 13;
    uint256 constant K = 13;
    uint256 constant W = 16;
    uint256 constant L = 32;           // ceil(128/4) = 32 message chains
    uint256 constant LEN1 = 32;        // ceil(n_bits/log2(w)) = 32
    uint256 constant TARGET_SUM = 240; // (w-1)*len1/2 = 15*32/2 = 240
    uint256 constant Z = 0;
    uint256 constant M_MAX = 121;
    uint256 constant TREE_HEIGHT = A;

    uint256 constant PORS_START = N;
    uint256 constant AUTH_START = N + K * N;
    uint256 constant HT_START = AUTH_START + M_MAX * N;
    uint256 constant LAYER_SIZE = L * N + 4 + SUBTREE_H * N;
    uint256 constant SIG_SIZE = HT_START + D * LAYER_SIZE;

    bytes32 public pkSeed;
    bytes32 public pkRoot;

    constructor(bytes32 _seed, bytes32 _root) {
        pkSeed = _seed;
        pkRoot = _root;
    }

    function _readN(bytes calldata sig, uint256 offset) internal pure returns (bytes32 val) {
        bytes16 v = bytes16(sig[offset:offset + 16]);
        val = bytes32(v);
    }

    function verify(bytes32 message, bytes calldata sig) external view returns (bool valid) {
        require(sig.length == SIG_SIZE, "Invalid sig length");

        bytes32 seed = pkSeed;
        bytes32 root = pkRoot;

        bytes32 R = _readN(sig, 0);
        bytes32 digest = TweakableHash.hMsg(seed, root, R, message);

        uint256 htIdx;
        assembly ("memory-safe") {
            htIdx := and(shr(169, digest), sub(shl(18, 1), 1))
        }

        // PORS+FP: parse secrets, compute leaves, extract indices, Octopus reconstruct
        bytes32 porsPk = _verifyPors(seed, digest, sig);

        // Hypertree: d layers of WOTS+C + Merkle
        bytes32 currentNode = porsPk;
        uint256 idxTree = htIdx;
        uint256 offset = HT_START;

        WotsPlusC.Params memory wotsParams = WotsPlusC.Params({
            w: W, l: L, len1: LEN1, targetSum: TARGET_SUM, z: Z
        });

        for (uint256 layer = 0; layer < D; layer++) {
            uint256 idxLeaf = idxTree & ((1 << SUBTREE_H) - 1);
            idxTree = idxTree >> SUBTREE_H;

            (bytes32 layerRoot, uint256 newOffset) = _verifyHtLayer(
                seed, sig, offset, layer, idxTree, idxLeaf, currentNode, wotsParams
            );
            currentNode = layerRoot;
            offset = newOffset;
        }

        valid = (currentNode == root);
    }

    function _verifyPors(
        bytes32 seed,
        bytes32 digest,
        bytes calldata sig
    ) internal pure returns (bytes32 porsPk) {
        uint256[] memory leafIndices = _extractIndices(digest);

        // Parse secrets and compute leaf hashes at digest-derived indices
        bytes32[] memory leafHashes = new bytes32[](K);
        for (uint256 i = 0; i < K; i++) {
            bytes32 secretVal = _readN(sig, PORS_START + i * N);
            bytes32 leafAdrs = TweakableHash.makeAdrs(
                0, 0, TweakableHash.ADRS_PORS, 0, 0, 0, uint32(leafIndices[i])
            );
            leafHashes[i] = TweakableHash.th(seed, leafAdrs, secretVal);
        }

        // Sort indices and corresponding leaf hashes together
        bytes32[] memory sortedHashes = _sortIndicesAndHashes(leafIndices, leafHashes);

        // Octopus reconstruction
        porsPk = _octopusReconstruct(seed, leafIndices, sortedHashes, sig);
    }

    function _extractIndices(
        bytes32 digest
    ) internal pure returns (uint256[] memory indices) {
        indices = new uint256[](K);
        uint256 totalLeaves = 1 << TREE_HEIGHT;
        uint256 count = 0;
        uint256 nonce = 0;

        while (count < K) {
            bytes32 extended;
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, digest)
                mstore(add(m, 0x20), nonce)
                extended := keccak256(m, 0x40)
            }
            uint256 bits = uint256(extended);
            for (uint256 b = 0; b + TREE_HEIGHT <= 256 && count < K; b += TREE_HEIGHT) {
                uint256 candidate = (bits >> b) & ((1 << TREE_HEIGHT) - 1);
                if (candidate < totalLeaves) {
                    bool dup = false;
                    for (uint256 j = 0; j < count; j++) {
                        if (indices[j] == candidate) { dup = true; break; }
                    }
                    if (!dup) {
                        indices[count] = candidate;
                        count++;
                    }
                }
            }
            nonce++;
        }
    }

    function _sortIndicesAndHashes(
        uint256[] memory indices,
        bytes32[] memory leafHashes
    ) internal pure returns (bytes32[] memory sorted) {
        // Sort indices and hashes together
        for (uint256 i = 1; i < K; i++) {
            uint256 key = indices[i];
            bytes32 keyHash = leafHashes[i];
            uint256 j = i;
            while (j > 0 && indices[j - 1] > key) {
                indices[j] = indices[j - 1];
                leafHashes[j] = leafHashes[j - 1];
                j--;
            }
            indices[j] = key;
            leafHashes[j] = keyHash;
        }
        sorted = leafHashes;
    }

    function _octopusReconstruct(
        bytes32 seed,
        uint256[] memory indices,
        bytes32[] memory hashes,
        bytes calldata sig
    ) internal pure returns (bytes32 root) {
        uint256 currentCount = K;
        uint256[] memory currentIndices = new uint256[](K + M_MAX);
        bytes32[] memory currentHashes = new bytes32[](K + M_MAX);
        for (uint256 i = 0; i < K; i++) {
            currentIndices[i] = indices[i];
            currentHashes[i] = hashes[i];
        }

        uint256 authIdx = 0;

        for (uint256 level = 0; level < TREE_HEIGHT; level++) {
            uint256 newCount = 0;
            uint256 j = 0;
            while (j < currentCount) {
                uint256 idx = currentIndices[j];
                uint256 sibling = idx ^ 1;
                uint256 parent = idx >> 1;

                bytes32 nodeAdrs = TweakableHash.makeAdrs(
                    0, 0, TweakableHash.ADRS_TREE, 0, 0, uint32(level + 1), uint32(parent)
                );

                if (j + 1 < currentCount && currentIndices[j + 1] == sibling) {
                    bytes32 left = idx < sibling ? currentHashes[j] : currentHashes[j + 1];
                    bytes32 right = idx < sibling ? currentHashes[j + 1] : currentHashes[j];
                    currentHashes[newCount] = TweakableHash.thPair(seed, nodeAdrs, left, right);
                    currentIndices[newCount] = parent;
                    newCount++;
                    j += 2;
                } else {
                    bytes32 siblingHash = _readN(sig, AUTH_START + authIdx * N);
                    authIdx++;
                    bytes32 left = (idx & 1 == 0) ? currentHashes[j] : siblingHash;
                    bytes32 right = (idx & 1 == 0) ? siblingHash : currentHashes[j];
                    currentHashes[newCount] = TweakableHash.thPair(seed, nodeAdrs, left, right);
                    currentIndices[newCount] = parent;
                    newCount++;
                    j += 1;
                }
            }
            currentCount = newCount;
        }
        require(currentCount == 1, "PORS root fail");
        root = currentHashes[0];
    }

    function _verifyHtLayer(
        bytes32 seed,
        bytes calldata sig,
        uint256 offset,
        uint256 layer,
        uint256 idxTree,
        uint256 idxLeaf,
        bytes32 currentNode,
        WotsPlusC.Params memory wotsParams
    ) internal pure returns (bytes32 layerRoot, uint256 newOffset) {
        bytes32[] memory wotsSigma = new bytes32[](L);
        for (uint256 i = 0; i < L; i++) {
            wotsSigma[i] = _readN(sig, offset);
            offset += N;
        }
        uint32 wotsCount = uint32(bytes4(sig[offset:offset + 4]));
        offset += 4;

        bytes32[] memory authPath = new bytes32[](SUBTREE_H);
        for (uint256 i = 0; i < SUBTREE_H; i++) {
            authPath[i] = _readN(sig, offset);
            offset += N;
        }

        bytes32 wotsAdrs = TweakableHash.makeAdrs(
            uint32(layer), uint64(idxTree), TweakableHash.ADRS_WOTS,
            uint32(idxLeaf), 0, 0, 0
        );
        bytes32 wotsPk = WotsPlusC.verify(
            seed, wotsAdrs, currentNode, wotsSigma, wotsCount, wotsParams
        );

        bytes32 treeAdrs = TweakableHash.makeAdrs(
            uint32(layer), uint64(idxTree), TweakableHash.ADRS_TREE,
            0, 0, 0, 0
        );
        layerRoot = TweakableHash.merkleAuthPath(seed, treeAdrs, wotsPk, authPath, idxLeaf);
        newOffset = offset;
    }
}
