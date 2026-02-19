// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TweakableHash} from "./TweakableHash.sol";

/// @title WotsPlusC - WOTS+C verification (checksum-less WOTS with grinding)
/// @notice Implements WOTS+C from ePrint 2025/2203: the checksum chains are replaced
///         by a nonce `count` that the signer grinds until the base-w digit encoding
///         satisfies a fixed-sum constraint (S_w,n) and z zero-chain constraints.
/// @dev For w=16: logW=4, len1=ceil(n/logW)=32, l=len1-z. Digest is keccak256 output
///      from which 32 base-16 digits are extracted (lower 128 bits used).
///      The verifier checks sum + zero constraints, then completes l chains.
///      No checksum chains needed.
library WotsPlusC {
    /// @notice Verify a WOTS+C signature and return the reconstructed WOTS public key
    /// @param seed PK.seed
    /// @param adrs ADRS with layer/tree set, type=WOTS(0)
    /// @param msgHash The message being signed (output of previous layer or FORS/PORS PK)
    /// @param sigma Array of l chain values from signature
    /// @param count Grinding nonce from signature
    /// @param params Packed parameters: w, l, len1, targetSum, z
    /// @return wotsPk Reconstructed WOTS+C public key
    function verify(
        bytes32 seed,
        bytes32 adrs,
        bytes32 msgHash,
        bytes32[] memory sigma,
        uint256 count,
        Params memory params
    ) internal pure returns (bytes32 wotsPk) {
        require(sigma.length == params.l, "WOTS+C: wrong sigma length");

        // Step 1: Compute constrained digest d = Th(seed, adrs*, msgHash || count)
        bytes32 d;
        {
            bytes32 hashAdrs = TweakableHash.makeAdrs(
                uint32(uint256(adrs) >> 224),       // layer
                uint64(uint256(adrs) >> 160),       // tree
                0,                                   // WOTS type
                uint32(uint256(adrs) >> 96),         // key pair
                0, 0, 0
            );
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, seed)
                mstore(add(m, 0x20), hashAdrs)
                mstore(add(m, 0x40), msgHash)
                mstore(add(m, 0x60), count)
                d := keccak256(m, 0x80)
            }
        }

        // Step 2: Extract base-w digits from d and validate constraints
        uint256 logW = _log2(params.w);
        uint256 wMask = params.w - 1;
        uint256 digitSum = 0;
        uint256[] memory digits = new uint256[](params.len1);

        // Extract digits and accumulate sum in one pass
        {
            uint256 dVal = uint256(d);
            for (uint256 i = 0; i < params.len1; i++) {
                uint256 digit = (dVal >> (i * logW)) & wMask;
                digits[i] = digit;
                digitSum += digit;
            }
        }

        // Step 3: Enforce WOTS+C constraints — reject invalid signatures early
        require(digitSum == params.targetSum, "WOTS+C: sum constraint violated");

        // Zero-chain constraint: last z digits must be 0
        for (uint256 i = params.len1 - params.z; i < params.len1; i++) {
            require(digits[i] == 0, "WOTS+C: zero-chain violated");
        }

        // Step 4: Complete l chains (no checksum chains needed)
        bytes32[] memory pkElements = new bytes32[](params.l);
        for (uint256 i = 0; i < params.l; i++) {
            uint256 steps = params.w - 1 - digits[i];
            bytes32 chainAdrs = TweakableHash.setChainIndex(adrs, uint32(i));
            pkElements[i] = TweakableHash.chainHash(seed, chainAdrs, sigma[i], digits[i], steps);
        }

        // Step 5: Compress to WOTS+C public key
        bytes32 pkAdrs = TweakableHash.makeAdrs(
            uint32(uint256(adrs) >> 224),
            uint64(uint256(adrs) >> 160),
            TweakableHash.ADRS_WOTS_PK,
            uint32(uint256(adrs) >> 96),
            0, 0, 0
        );
        wotsPk = TweakableHash.thMulti(seed, pkAdrs, pkElements);
    }

    struct Params {
        uint256 w;         // Winternitz parameter (16 for all our configs)
        uint256 l;         // Number of chains = len1 - z
        uint256 len1;      // Number of message digits = ceil(n/log2(w))
        uint256 targetSum; // S_w,n fixed-sum constraint
        uint256 z;         // Number of forced zero-chains
    }

    function _log2(uint256 x) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            r := 0
            let v := x
            // Only handles powers of 2 for w = {4, 16, 256}
            if gt(v, 0xFF) { r := add(r, 8) v := shr(8, v) }
            if gt(v, 0x0F) { r := add(r, 4) v := shr(4, v) }
            if gt(v, 0x03) { r := add(r, 2) v := shr(2, v) }
            if gt(v, 0x01) { r := add(r, 1) }
        }
    }
}
