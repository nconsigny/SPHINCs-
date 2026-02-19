// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SphincsWcPfp18} from "../src/SphincsWcPfp18.sol";
import {SphincsWcFc18} from "../src/SphincsWcFc18.sol";
import {SphincsWcPfp27} from "../src/SphincsWcPfp27.sol";
import {SphincsWcPfp18Asm} from "../src/SphincsWcPfp18Asm.sol";
import {SphincsWcFc18Asm} from "../src/SphincsWcFc18Asm.sol";
import {SphincsWcPfp27Asm} from "../src/SphincsWcPfp27Asm.sol";

/// @title AsmBenchmark - Side-by-side gas comparison: Solidity vs Assembly verifiers
/// @notice Run with: forge test --match-contract AsmBenchmark -vv
///         For mainnet fork: forge test --match-contract AsmBenchmark -vv --fork-url https://eth.llamarpc.com
/// @dev Both Solidity and Asm contracts receive identical random signatures.
///      They will revert (invalid sig) but exercise the full computation path.
///      Gas measured includes all execution up to the revert point.
contract AsmBenchmark is Test {
    bytes32 constant SEED = keccak256("benchmark_seed");
    bytes32 constant ROOT = keccak256("dummy_root");

    // EIP-7623 calldata floor constants
    uint256 constant GAS_CD_NZ_FLOOR = 60;
    uint256 constant GAS_CD_Z_FLOOR  = 15;
    uint256 constant GAS_CD_NZ_STD   = 16;
    uint256 constant GAS_CD_Z_STD    = 4;

    function _randomSig(uint256 size) internal pure returns (bytes memory sig) {
        sig = new bytes(size);
        for (uint256 i = 0; i < size; i += 32) {
            bytes32 chunk = keccak256(abi.encodePacked("asm_bench_sig", i));
            uint256 toCopy = size - i < 32 ? size - i : 32;
            for (uint256 j = 0; j < toCopy; j++) {
                sig[i + j] = chunk[j];
            }
        }
    }

    function _calldataGas(uint256 sigSize)
        internal pure returns (uint256 stdCd, uint256 floorCd)
    {
        uint256 nz = (sigSize * 97) / 100 + 100; // sig NZ + overhead (selector+msg+ABI)
        uint256 z = sigSize - (sigSize * 97) / 100;
        stdCd = nz * GAS_CD_NZ_STD + z * GAS_CD_Z_STD;
        floorCd = nz * GAS_CD_NZ_FLOOR + z * GAS_CD_Z_FLOOR;
    }

    function _reportGas(
        string memory name,
        uint256 sigSize,
        uint256 solGas,
        uint256 asmGas
    ) internal pure {
        (uint256 stdCd, uint256 floorCd) = _calldataGas(sigSize);
        uint256 floorPath = 21000 + floorCd;

        console.log("  %s:", name);
        console.log("    Sig: %d bytes", sigSize);
        console.log("    Solidity exec: %d", solGas);
        console.log("    Asm exec: %d", asmGas);
        console.log("    Speedup: %dx", solGas / (asmGas > 0 ? asmGas : 1));
        console.log("    Sol tx: %d", _maxU(21000 + stdCd + solGas, floorPath));
        console.log("    Asm tx: %d", _maxU(21000 + stdCd + asmGas, floorPath));
        console.log("    Floor:  %d", floorPath);
        if (21000 + stdCd + asmGas <= floorPath) {
            console.log("    >>> ASM FLOOR-DOMINATED (exec is free)");
        }
        console.log("");
    }

    function _maxU(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    // ================================================================
    //  Contract 2: W+C + FORS+C (h=18, d=2) — 4040 bytes
    // ================================================================

    function test_C2_Solidity_vs_Asm() public {
        uint256 sigSize = 4040;
        bytes32 message = keccak256("c2_bench_msg");

        // Grind R for FORS+C forced-zero constraint (same as E2ESimulation)
        bytes memory sig = _randomSig(sigSize);
        {
            uint256 kIdx = 12;
            uint256 a = 13;
            uint256 aMask = (1 << a) - 1;
            for (uint256 nonce = 0; nonce < 100000; nonce++) {
                bytes32 raw = keccak256(abi.encodePacked("R_grind_asm_c2", nonce));
                bytes32 candidateR = raw & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;
                bytes32 dg = _hMsg(SEED, ROOT, candidateR, message);
                uint256 lastIdx = (uint256(dg) >> (kIdx * a)) & aMask;
                if (lastIdx == 0) {
                    for (uint256 i = 0; i < 16; i++) {
                        sig[i] = candidateR[i];
                    }
                    break;
                }
            }
        }

        // Solidity version
        SphincsWcFc18 sol = new SphincsWcFc18(SEED, ROOT);
        uint256 g1 = gasleft();
        try sol.verify(message, sig) {} catch {}
        uint256 solGas = g1 - gasleft();

        // Assembly version
        SphincsWcFc18Asm asm_ = new SphincsWcFc18Asm(SEED, ROOT);
        uint256 g2 = gasleft();
        try asm_.verify(message, sig) {} catch {}
        uint256 asmGas = g2 - gasleft();

        console.log("================================================================");
        console.log("  ASM vs SOLIDITY: Side-by-Side Gas Comparison");
        console.log("  (EIP-7623: 60/15 calldata floor, keccak: 30+6/word)");
        console.log("================================================================");
        console.log("");

        _reportGas("C2 W+C_F+C (h=18,d=2)", sigSize, solGas, asmGas);
    }

    // ================================================================
    //  Contract 1: W+C + P+FP (h=18, d=2) — 3480 bytes
    // ================================================================

    function test_C1_Solidity_vs_Asm() public {
        uint256 sigSize = 3480;
        bytes32 message = keccak256("c1_bench_msg");
        bytes memory sig = _randomSig(sigSize);

        SphincsWcPfp18 sol = new SphincsWcPfp18(SEED, ROOT);
        uint256 g1 = gasleft();
        try sol.verify(message, sig) {} catch {}
        uint256 solGas = g1 - gasleft();

        SphincsWcPfp18Asm asm_ = new SphincsWcPfp18Asm(SEED, ROOT);
        uint256 g2 = gasleft();
        try asm_.verify(message, sig) {} catch {}
        uint256 asmGas = g2 - gasleft();

        console.log("================================================================");
        console.log("  ASM vs SOLIDITY: Contract 1");
        console.log("================================================================");
        console.log("");
        _reportGas("C1 W+C_P+FP (h=18,d=2)", sigSize, solGas, asmGas);
    }

    // ================================================================
    //  Contract 3: W+C + P+FP (h=27, d=3) — 3260 bytes
    // ================================================================

    function test_C3_Solidity_vs_Asm() public {
        uint256 sigSize = 3260;
        bytes32 message = keccak256("c3_bench_msg");
        bytes memory sig = _randomSig(sigSize);

        SphincsWcPfp27 sol = new SphincsWcPfp27(SEED, ROOT);
        uint256 g1 = gasleft();
        try sol.verify(message, sig) {} catch {}
        uint256 solGas = g1 - gasleft();

        SphincsWcPfp27Asm asm_ = new SphincsWcPfp27Asm(SEED, ROOT);
        uint256 g2 = gasleft();
        try asm_.verify(message, sig) {} catch {}
        uint256 asmGas = g2 - gasleft();

        console.log("================================================================");
        console.log("  ASM vs SOLIDITY: Contract 3");
        console.log("================================================================");
        console.log("");
        _reportGas("C3 W+C_P+FP (h=27,d=3)", sigSize, solGas, asmGas);
    }

    // ================================================================
    //  Full comparison table
    // ================================================================

    function test_FullComparison() public {
        bytes32 msg1 = keccak256("full_cmp_c1");
        bytes32 msg2 = keccak256("full_cmp_c2");
        bytes32 msg3 = keccak256("full_cmp_c3");

        // C1
        bytes memory sig1 = _randomSig(3480);
        SphincsWcPfp18 sol1 = new SphincsWcPfp18(SEED, ROOT);
        SphincsWcPfp18Asm asm1 = new SphincsWcPfp18Asm(SEED, ROOT);
        uint256 g; uint256 solG1; uint256 asmG1;
        g = gasleft(); try sol1.verify(msg1, sig1) {} catch {} solG1 = g - gasleft();
        g = gasleft(); try asm1.verify(msg1, sig1) {} catch {} asmG1 = g - gasleft();

        // C2 (with FORS+C grind)
        bytes memory sig2 = _randomSig(4040);
        {
            for (uint256 nonce = 0; nonce < 100000; nonce++) {
                bytes32 raw = keccak256(abi.encodePacked("R_full_cmp_c2", nonce));
                bytes32 cR = raw & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;
                bytes32 dg = _hMsg(SEED, ROOT, cR, msg2);
                if ((uint256(dg) >> 156) & 0x1FFF == 0) {
                    for (uint256 i = 0; i < 16; i++) sig2[i] = cR[i];
                    break;
                }
            }
        }
        SphincsWcFc18 sol2 = new SphincsWcFc18(SEED, ROOT);
        SphincsWcFc18Asm asm2 = new SphincsWcFc18Asm(SEED, ROOT);
        uint256 solG2; uint256 asmG2;
        g = gasleft(); try sol2.verify(msg2, sig2) {} catch {} solG2 = g - gasleft();
        g = gasleft(); try asm2.verify(msg2, sig2) {} catch {} asmG2 = g - gasleft();

        // C3
        bytes memory sig3 = _randomSig(3260);
        SphincsWcPfp27 sol3 = new SphincsWcPfp27(SEED, ROOT);
        SphincsWcPfp27Asm asm3 = new SphincsWcPfp27Asm(SEED, ROOT);
        uint256 solG3; uint256 asmG3;
        g = gasleft(); try sol3.verify(msg3, sig3) {} catch {} solG3 = g - gasleft();
        g = gasleft(); try asm3.verify(msg3, sig3) {} catch {} asmG3 = g - gasleft();

        // Calldata
        (uint256 stdCd1, uint256 floorCd1) = _calldataGas(3480);
        (uint256 stdCd2, uint256 floorCd2) = _calldataGas(4040);
        (uint256 stdCd3, uint256 floorCd3) = _calldataGas(3260);

        console.log("================================================================");
        console.log("  FULL ASM vs SOLIDITY COMPARISON");
        console.log("  EIP-7623 floor: 60/15 | Standard: 16/4 | keccak: 30+6/word");
        console.log("================================================================");
        console.log("");
        console.log("  Contract  Sig(B)  Sol Exec    Asm Exec    Speedup");
        console.log("  -----------------------------------------------------------");
        console.log("  C1 P+FP   3480    %d    %d    %dx", solG1, asmG1, solG1 / (asmG1 > 0 ? asmG1 : 1));
        console.log("  C2 F+C    4040    %d    %d    %dx", solG2, asmG2, solG2 / (asmG2 > 0 ? asmG2 : 1));
        console.log("  C3 P+FP   3260    %d    %d    %dx", solG3, asmG3, solG3 / (asmG3 > 0 ? asmG3 : 1));
        console.log("");

        // EIP-7623 totals
        uint256[3] memory asmExec = [asmG1, asmG2, asmG3];
        uint256[3] memory solExec = [solG1, solG2, solG3];
        uint256[3] memory floors  = [floorCd1, floorCd2, floorCd3];
        uint256[3] memory stds    = [stdCd1, stdCd2, stdCd3];
        string[3] memory names = ["C1 P+FP", "C2 F+C ", "C3 P+FP"];
        uint256[3] memory papers  = [uint256(0), uint256(0), uint256(0)]; // TBD: recalculate with corrected WOTS+C params

        console.log("  EIP-7623 Transaction Gas:");
        console.log("  -----------------------------------------------------------");
        for (uint256 i = 0; i < 3; i++) {
            uint256 solStd  = 21000 + stds[i] + solExec[i];
            uint256 asmStd  = 21000 + stds[i] + asmExec[i];
            uint256 floor   = 21000 + floors[i];
            uint256 solTot  = solStd > floor ? solStd : floor;
            uint256 asmTot  = asmStd > floor ? asmStd : floor;
            string memory dom = asmStd <= floor ? "YES" : "NO";
            console.log("  %s:", names[i]);
            console.log("    Sol: %d | Asm: %d | Floor: %d", solTot, asmTot, floor);
            console.log("    Paper: %d | FloorDom: %s", papers[i], dom);
        }
        console.log("");
        console.log("  FloorDom=YES means asm execution fits within calldata floor:");
        console.log("  tx_gas = 21K + floor_calldata (execution is 'free')");
    }

    // ================================================================
    //  Helper: H_msg matches TweakableHash.hMsg
    // ================================================================
    function _hMsg(bytes32 seed, bytes32 r, bytes32 R, bytes32 message)
        internal pure returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), r)
            mstore(add(m, 0x40), R)
            mstore(add(m, 0x60), message)
            digest := keccak256(m, 0x80)
        }
    }
}
