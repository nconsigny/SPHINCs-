// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TweakableHash} from "./TweakableHash.sol";
import {WotsPlusC} from "./WotsPlusC.sol";

/// @title SphincsWcFc18 - Tweaked SPHINCS+ Verifier: W+C + FORS+C (h=18, d=2, a=13, k=13)
/// @notice Contract 2: WOTS+C with FORS+C. Sig: 4040 bytes.
contract SphincsWcFc18 {
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

    uint256 constant FORS_START = N;
    uint256 constant AUTH_START = N + K * N;
    uint256 constant HT_START = AUTH_START + (K - 1) * A * N;
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

        bytes32 forsPk = _verifyFors(seed, digest, sig);

        bytes32 currentNode = forsPk;
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

    function _verifyFors(
        bytes32 seed,
        bytes32 digest,
        bytes calldata sig
    ) internal pure returns (bytes32 forsPk) {
        uint256 aMask = (1 << A) - 1;
        uint256[] memory indices = new uint256[](K);
        {
            uint256 dVal = uint256(digest);
            for (uint256 i = 0; i < K; i++) {
                indices[i] = (dVal >> (i * A)) & aMask;
            }
        }

        require(indices[K - 1] == 0, "FORS+C: forced-zero violated");

        bytes32[] memory roots = new bytes32[](K);

        for (uint256 i = 0; i < K - 1; i++) {
            bytes32 secretVal = _readN(sig, FORS_START + i * N);
            bytes32 leafAdrs = TweakableHash.makeAdrs(
                0, 0, TweakableHash.ADRS_FORS_TREE, uint32(i), 0, 0, uint32(indices[i])
            );
            bytes32 leaf = TweakableHash.th(seed, leafAdrs, secretVal);

            bytes32[] memory authPath = new bytes32[](A);
            uint256 authBase = AUTH_START + i * A * N;
            for (uint256 j = 0; j < A; j++) {
                authPath[j] = _readN(sig, authBase + j * N);
            }

            bytes32 treeAdrs = TweakableHash.makeAdrs(
                0, 0, TweakableHash.ADRS_FORS_TREE, uint32(i), 0, 0, 0
            );
            roots[i] = TweakableHash.merkleAuthPath(seed, treeAdrs, leaf, authPath, indices[i]);
        }

        {
            bytes32 lastSecret = _readN(sig, FORS_START + (K - 1) * N);
            bytes32 lastAdrs = TweakableHash.makeAdrs(
                0, 0, TweakableHash.ADRS_FORS_TREE, uint32(K - 1), 0, 0, 0
            );
            roots[K - 1] = TweakableHash.th(seed, lastAdrs, lastSecret);
        }

        bytes32 rootsAdrs = TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_FORS_ROOTS, 0, 0, 0, 0);
        forsPk = TweakableHash.thMulti(seed, rootsAdrs, roots);
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
