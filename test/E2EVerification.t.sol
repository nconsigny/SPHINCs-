// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {SphincsC2} from "../src/SPHINCs-C2.sol";
import {SphincsC2Asm} from "../src/SPHINCs-C2Asm.sol";
import {SphincsC4} from "../src/SPHINCs-C4.sol";
import {SphincsC4Asm} from "../src/SPHINCs-C4Asm.sol";
import {SphincsC1} from "../src/SPHINCs-C1.sol";
import {SphincsC1Asm} from "../src/SPHINCs-C1Asm.sol";
import {SphincsC3} from "../src/SPHINCs-C3.sol";
import {SphincsC3Asm} from "../src/SPHINCs-C3Asm.sol";

/// @title E2EVerification - End-to-end verification using Python reference signer
/// @notice Calls the Python signer via FFI to get valid (seed, root, sig),
///         then verifies against both Solidity and Assembly contracts.
contract E2EVerification is Test {

    // ================================================================
    //  Helpers
    // ================================================================

    function _callSigner(string memory variant, bytes32 message)
        internal
        returns (bytes32 seed, bytes32 root, bytes memory sig)
    {
        string[] memory cmd = new string[](4);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/signer.py";
        cmd[2] = variant;
        cmd[3] = vm.toString(message);

        bytes memory result = vm.ffi(cmd);
        (seed, root, sig) = abi.decode(result, (bytes32, bytes32, bytes));
    }

    // ================================================================
    //  Contract 2: W+C + FORS+C (h=18, d=2) — 4264 bytes
    // ================================================================

    function test_C2_E2E() public {
        bytes32 message = keccak256("e2e_c2");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 2 (W+C + FORS+C)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c2", message);
        console.log("  Seed: %s", vm.toString(seed));
        console.log("  Root: %s", vm.toString(root));
        console.log("  Sig length: %d bytes", sig.length);

        // Solidity verification
        SphincsC2 sol = new SphincsC2(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C2 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        // Assembly verification
        SphincsC2Asm asm_ = new SphincsC2Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C2 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);

        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }

    // ================================================================
    //  Contract 1: W+C + P+FP (h=18, d=2) — 4296 bytes
    // ================================================================

    function test_C1_E2E() public {
        bytes32 message = keccak256("e2e_c1");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 1 (W+C + PORS+FP h=18)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c1", message);
        console.log("  Sig length: %d bytes", sig.length);

        SphincsC1 sol = new SphincsC1(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C1 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        SphincsC1Asm asm_ = new SphincsC1Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C1 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);
        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }

    // ================================================================
    //  Contract 4: W+C + FORS+C (h=30, d=3) — 3740 bytes
    // ================================================================

    function test_C4_E2E() public {
        bytes32 message = keccak256("e2e_c4");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 4 (W+C + FORS+C h=30)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c4", message);
        console.log("  Sig length: %d bytes", sig.length);

        SphincsC4 sol = new SphincsC4(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C4 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        SphincsC4Asm asm_ = new SphincsC4Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C4 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);
        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }

    // ================================================================
    //  Contract 3: W+C + P+FP (h=27, d=3) — 4188 bytes
    // ================================================================

    function test_C3_E2E() public {
        bytes32 message = keccak256("e2e_c3");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 3 (W+C + PORS+FP h=27)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c3", message);
        console.log("  Sig length: %d bytes", sig.length);

        SphincsC3 sol = new SphincsC3(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C3 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        SphincsC3Asm asm_ = new SphincsC3Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C3 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);
        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }
}
