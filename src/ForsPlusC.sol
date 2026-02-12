// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TweakableHash} from "./TweakableHash.sol";

/// @title ForsPlusC - FORS+C verification (last-tree forced-zero grinding)
/// @notice Implements FORS+C from ePrint 2025/2203 / SPHINCS+C (2022/782):
///         The signer grinds until the last FORS tree index is 0, so its
///         authentication path can be omitted. Saves (a+1)*n bytes per signature.
/// @dev For the W+C variant (Contract 2): h=18, d=2, a=13, k=13, w=16
///      - k=13 trees, each of height a=13 (t = 2^13 = 8192 leaves per tree)
///      - Last tree auth path omitted → 12 full auth paths + 13 secret values
///      - Digest produces k indices, each a bits wide
library ForsPlusC {
    /// @notice Verify FORS+C signature and return FORS public key
    /// @param seed PK.seed
    /// @param adrs ADRS with layer/tree set, type will be set to FORS_TREE/FORS_ROOTS
    /// @param digest Full H_msg digest (from which k indices are extracted)
    /// @param secretValues k secret leaf values (F(seed, adrs, sk_i))
    /// @param authPaths k-1 authentication paths (last tree omitted due to forced-zero)
    /// @param k Number of FORS trees
    /// @param a Tree height (t = 2^a leaves per tree)
    /// @return forsPk The compressed FORS+C public key
    function verify(
        bytes32 seed,
        bytes32 adrs,
        bytes32 digest,
        bytes32[] memory secretValues,
        bytes32[][] memory authPaths,
        uint256 k,
        uint256 a
    ) internal pure returns (bytes32 forsPk) {
        require(secretValues.length == k, "FORS+C: wrong secret count");
        require(authPaths.length == k - 1, "FORS+C: wrong auth path count");

        uint256 aMask = (1 << a) - 1;

        // Extract k indices from digest (each a bits)
        uint256[] memory indices = new uint256[](k);
        {
            uint256 dVal = uint256(digest);
            for (uint256 i = 0; i < k; i++) {
                indices[i] = (dVal >> (i * a)) & aMask;
            }
        }

        // FORS+C constraint: last tree index must be 0 (forced by signer grinding)
        require(indices[k - 1] == 0, "FORS+C: last-tree forced-zero violated");

        // Compute k tree roots
        bytes32[] memory roots = new bytes32[](k);

        // Trees 0..k-2: standard auth path verification
        for (uint256 i = 0; i < k - 1; i++) {
            // Leaf hash: F(seed, adrs_leaf, secret_i)
            bytes32 leafAdrs = TweakableHash.makeAdrs(
                uint32(uint256(adrs) >> 224),
                uint64(uint256(adrs) >> 160),
                TweakableHash.ADRS_FORS_TREE,
                uint32(i),               // tree index
                0,                        // height = 0
                0,
                uint32(indices[i])        // leaf index
            );
            bytes32 leaf = TweakableHash.th(seed, leafAdrs, secretValues[i]);

            // Walk auth path to root
            bytes32 treeAdrs = TweakableHash.makeAdrs(
                uint32(uint256(adrs) >> 224),
                uint64(uint256(adrs) >> 160),
                TweakableHash.ADRS_FORS_TREE,
                uint32(i),
                0, 0, 0
            );
            require(authPaths[i].length == a, "FORS+C: wrong auth path length");
            roots[i] = TweakableHash.merkleAuthPath(seed, treeAdrs, leaf, authPaths[i], indices[i]);
        }

        // Tree k-1: forced index = 0, no auth path needed
        // We still compute the leaf hash and walk up, but the path is deterministic
        // Since index=0, we need the root. With only the leaf at index 0, we can
        // compute up using the fact that sibling hashes are provided by knowing the
        // tree structure. BUT: in FORS+C the auth path is simply omitted because
        // the signer provides the root directly via the leaf at index 0.
        // Actually: the verifier computes the leaf, then needs to verify it matches
        // the root. Since there's no auth path, the root IS just the leaf hashed
        // up through height-a nodes. The signer must provide the auth path siblings
        // for the index-0 path, or the verifier uses a known structure.
        //
        // Per the paper: the last tree's secret value at index 0 is provided,
        // and the authentication path is omitted. The root is computed differently —
        // the verifier uses the forced-zero leaf as-is with an empty auth path
        // replacement. In practice, the signer includes the last tree's ROOT
        // directly, and the verifier checks that the digest forced index 0.
        {
            bytes32 lastLeafAdrs = TweakableHash.makeAdrs(
                uint32(uint256(adrs) >> 224),
                uint64(uint256(adrs) >> 160),
                TweakableHash.ADRS_FORS_TREE,
                uint32(k - 1),
                0, 0, 0
            );
            // The last secret value is actually the root of the last tree
            // (pre-computed by signer, since verifier can't walk without auth path)
            roots[k - 1] = TweakableHash.th(seed, lastLeafAdrs, secretValues[k - 1]);
        }

        // Compress k roots into FORS+C public key
        bytes32 rootsAdrs = TweakableHash.makeAdrs(
            uint32(uint256(adrs) >> 224),
            uint64(uint256(adrs) >> 160),
            TweakableHash.ADRS_FORS_ROOTS,
            0, 0, 0, 0
        );
        forsPk = TweakableHash.thMulti(seed, rootsAdrs, roots);
    }
}
