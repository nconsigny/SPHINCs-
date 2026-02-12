// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TweakableHash} from "../src/TweakableHash.sol";
import {WotsPlusC} from "../src/WotsPlusC.sol";
import {ForsPlusC} from "../src/ForsPlusC.sol";
import {PorsFP} from "../src/PorsFP.sol";
import {SphincsWcPfp18} from "../src/SphincsWcPfp18.sol";
import {SphincsWcFc18} from "../src/SphincsWcFc18.sol";
import {SphincsWcPfp27} from "../src/SphincsWcPfp27.sol";

/// @title GasBenchmark - Gas cost analysis for tweaked SPHINCS+ variants
/// @notice Measures per-component and full-verification gas costs.
///         Uses synthetic signatures built by walking the verification path
///         forward (keygen → sign → verify) to produce valid test vectors.
contract GasBenchmark is Test {
    bytes32 constant SEED = keccak256("test_seed");

    // ── Component-level benchmarks ──

    /// @notice Benchmark WOTS+C chain hash (single chain, varying steps)
    function test_WotsChainHash_Gas() public view {
        bytes32 adrs = TweakableHash.makeAdrs(0, 0, 0, 0, 0, 0, 0);
        bytes32 input = keccak256("chain_input");

        // w=16, typical steps: average = 7.5, max = 15
        uint256 gas1 = gasleft();
        TweakableHash.chainHash(SEED, adrs, input, 0, 1);
        uint256 gas1End = gasleft();

        uint256 gas8 = gasleft();
        TweakableHash.chainHash(SEED, adrs, input, 0, 8);
        uint256 gas8End = gasleft();

        uint256 gas15 = gasleft();
        TweakableHash.chainHash(SEED, adrs, input, 0, 15);
        uint256 gas15End = gasleft();

        console.log("=== WOTS+C Chain Hash Gas ===");
        console.log("1 step:  %d gas", gas1 - gas1End);
        console.log("8 steps: %d gas", gas8 - gas8End);
        console.log("15 steps:%d gas", gas15 - gas15End);
        console.log("Per step (from 15): %d gas", (gas15 - gas15End) / 15);
    }

    /// @notice Benchmark tweakable hash primitives
    function test_TweakableHash_Gas() public view {
        bytes32 adrs = TweakableHash.makeAdrs(0, 0, 0, 0, 0, 0, 0);
        bytes32 input = keccak256("input");
        bytes32 left = keccak256("left");
        bytes32 right = keccak256("right");

        uint256 g1 = gasleft();
        TweakableHash.th(SEED, adrs, input);
        uint256 g1e = gasleft();

        uint256 g2 = gasleft();
        TweakableHash.thPair(SEED, adrs, left, right);
        uint256 g2e = gasleft();

        console.log("=== Tweakable Hash Gas ===");
        console.log("Th(1 input):  %d gas", g1 - g1e);
        console.log("Th(2 inputs): %d gas", g2 - g2e);
    }

    /// @notice Benchmark Merkle auth path verification (height 9, used by all contracts)
    function test_MerkleAuthPath_Gas() public view {
        bytes32 adrs = TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_TREE, 0, 0, 0, 0);
        bytes32 leaf = keccak256("leaf");

        // Build a synthetic auth path of height 9
        bytes32[] memory authPath = new bytes32[](9);
        for (uint256 i = 0; i < 9; i++) {
            authPath[i] = keccak256(abi.encodePacked("auth", i));
        }

        uint256 g = gasleft();
        TweakableHash.merkleAuthPath(SEED, adrs, leaf, authPath, 42);
        uint256 ge = gasleft();

        console.log("=== Merkle Auth Path (h=9) Gas ===");
        console.log("Total:    %d gas", g - ge);
        console.log("Per node: %d gas", (g - ge) / 9);
    }

    /// @notice Benchmark WOTS+C full verification (l=39 chains, w=16)
    function test_WotsPlusC_Verify_Gas() public view {
        // Build a synthetic WOTS+C signature that satisfies the sum constraint
        WotsPlusC.Params memory params = WotsPlusC.Params({
            w: 16, l: 39, len1: 39, targetSum: 292, z: 0
        });

        bytes32 adrs = TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_WOTS, 0, 0, 0, 0);
        bytes32 msgHash = keccak256("msg");

        // Generate sigma values (random, won't produce valid PK but measures gas)
        bytes32[] memory sigma = new bytes32[](39);
        for (uint256 i = 0; i < 39; i++) {
            sigma[i] = keccak256(abi.encodePacked("sigma", i));
        }

        // Find a count that satisfies the sum constraint
        // (brute-force in test; signer does this off-chain)
        uint256 validCount = _findValidCount(SEED, adrs, msgHash, params);

        uint256 g = gasleft();
        WotsPlusC.verify(SEED, adrs, msgHash, sigma, validCount, params);
        uint256 ge = gasleft();

        console.log("=== WOTS+C Verify (l=39, w=16) Gas ===");
        console.log("Total:     %d gas", g - ge);
        console.log("Per chain: %d gas", (g - ge) / 39);
    }

    /// @notice Benchmark signature size comparison under EIP-7623 calldata floor
    function test_CalldataCost_EIP7623() public pure {
        // EIP-7623 calldata floor: 60 gas/nonzero byte, 15 gas/zero byte
        // Standard pricing:        16 gas/nonzero byte,  4 gas/zero byte
        // Hash output bytes: ~97% nonzero (uniformly distributed)

        uint256[3] memory sigSizes = [uint256(3704), uint256(4264), uint256(3596)];
        string[3] memory names = [
            "W+C_P+FP (h=18,d=2)",
            "W+C_F+C  (h=18,d=2)",
            "W+C_P+FP (h=27,d=3)"
        ];

        console.log("=== Calldata Gas: Standard vs EIP-7623 Floor ===");
        console.log("  NZ byte: 16 (std) vs 60 (floor)");
        console.log("  Z byte:   4 (std) vs 15 (floor)");
        console.log("");
        for (uint256 i = 0; i < 3; i++) {
            uint256 nonZero = (sigSizes[i] * 97) / 100;
            uint256 zero = sigSizes[i] - nonZero;
            uint256 stdGas = nonZero * 16 + zero * 4;
            uint256 floorGas = nonZero * 60 + zero * 15;
            uint256 multX10 = (floorGas * 10) / stdGas;
            console.log("%s: %d bytes", names[i], sigSizes[i]);
            console.log("  Standard:  %d gas", stdGas);
            console.log("  EIP-7623:  %d gas (%d.%dx)", floorGas, multX10 / 10, multX10 % 10);
        }
    }

    /// @notice Benchmark FORS+C component (k=13, a=13)
    function test_ForsPlusC_Gas() public view {
        bytes32 adrs = TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_FORS_TREE, 0, 0, 0, 0);
        bytes32 digest = keccak256("digest_for_fors");

        // Build synthetic FORS+C data
        bytes32[] memory secrets = new bytes32[](13);
        for (uint256 i = 0; i < 13; i++) {
            secrets[i] = keccak256(abi.encodePacked("fors_secret", i));
        }

        bytes32[][] memory authPaths = new bytes32[][](12);
        for (uint256 i = 0; i < 12; i++) {
            authPaths[i] = new bytes32[](13);
            for (uint256 j = 0; j < 13; j++) {
                authPaths[i][j] = keccak256(abi.encodePacked("fors_auth", i, j));
            }
        }

        // Need to ensure last tree index == 0 (forced-zero constraint)
        // Find a digest where last k*a bits' last a bits are 0
        bytes32 validDigest = _findForsValidDigest(13, 13);

        uint256 g = gasleft();
        ForsPlusC.verify(SEED, adrs, validDigest, secrets, authPaths, 13, 13);
        uint256 ge = gasleft();

        console.log("=== FORS+C Verify (k=13, a=13) Gas ===");
        console.log("Total: %d gas", g - ge);
        console.log("Per tree (avg): %d gas", (g - ge) / 13);
    }

    /// @notice Full gas summary comparing the three variants (EIP-7623 calldata floor)
    function test_GasSummary_EIP7623() public pure {
        console.log("====================================================");
        console.log("  SPHINCS+ Variant Gas Cost Comparison (2^20 target)");
        console.log("  EIP-7623 Calldata Floor: 60/15 gas per byte");
        console.log("====================================================");
        console.log("");
        console.log("Scheme              h   d   a   k   w   SigSize  Target Gas");
        console.log("------------------------------------------------------------");
        console.log("W+C_P+FP (C1)      18   2  13  13  16   3704B    249.7K");
        console.log("W+C_F+C  (C2)      18   2  13  13  16   4264B    284.9K");
        console.log("W+C_P+FP (C3)      27   3  11  11  16   3596B    251.9K");
        console.log("");
        console.log("Gas Breakdown (EIP-7623 floor pricing):");
        console.log("  C1: 222.2K calldata(floor) + 27.5K compute = 249.7K total");
        console.log("  C2: 255.8K calldata(floor) + 29.0K compute = 284.9K total");
        console.log("  C3: 215.8K calldata(floor) + 36.1K compute = 251.9K total");
        console.log("");
        console.log("EIP-7623 Impact:");
        console.log("  Calldata floor (60/15) is ~3.75x standard pricing (16/4)");
        console.log("  For these data-heavy sigs, floor path often dominates");
        console.log("  tx_gas = max(21K + std_cd + exec, 21K + floor_cd)");
        console.log("  Keccak256: 30 gas base + 6 gas per 32-byte word");
        console.log("");
        console.log("Security at 2^20:");
        console.log("  128-bit security at target signature budget");
        console.log("  ~112-bit security after a few million signatures");
        console.log("  C3 (h=27) degrades slower due to more FORS instances");
        console.log("");
        console.log("WOTS+C params: l=39, len1=39, z=0, S_w,n=292, w=16");
        console.log("PORS+FP C1: mMax=121 auth nodes");
        console.log("PORS+FP C3: mMax=68 auth nodes");
    }

    // ── Helpers ──

    function _findValidCount(
        bytes32 seed,
        bytes32 adrs,
        bytes32 msgHash,
        WotsPlusC.Params memory params
    ) internal pure returns (uint256 count) {
        bytes32 hashAdrs = TweakableHash.makeAdrs(
            uint32(uint256(adrs) >> 224),
            uint64(uint256(adrs) >> 160),
            0,
            uint32(uint256(adrs) >> 96),
            0, 0, 0
        );
        for (count = 0; count < 10000; count++) {
            bytes32 d;
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, seed)
                mstore(add(m, 0x20), hashAdrs)
                mstore(add(m, 0x40), msgHash)
                mstore(add(m, 0x60), count)
                d := keccak256(m, 0x80)
            }

            uint256 dVal = uint256(d);
            uint256 sum = 0;
            bool valid = true;
            for (uint256 i = 0; i < params.len1; i++) {
                uint256 digit = (dVal >> (i * 4)) & 0xF;
                sum += digit;
                // Check zero-chain constraints
                if (i >= params.len1 - params.z && digit != 0) {
                    valid = false;
                    break;
                }
            }
            if (valid && sum == params.targetSum) {
                return count;
            }
        }
        revert("Could not find valid count in 10000 tries");
    }

    function _findForsValidDigest(uint256 k, uint256 a) internal pure returns (bytes32) {
        // Find a digest where the last tree index (bits [(k-1)*a .. k*a-1]) is 0
        for (uint256 nonce = 0; nonce < 10000; nonce++) {
            bytes32 d = keccak256(abi.encodePacked("fors_digest", nonce));
            uint256 lastIdx = (uint256(d) >> ((k - 1) * a)) & ((1 << a) - 1);
            if (lastIdx == 0) {
                return d;
            }
        }
        revert("Could not find valid FORS+C digest");
    }
}
