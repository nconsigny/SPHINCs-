// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {SphincsWcFc18} from "../src/SphincsWcFc18.sol";
import {SphincsWcFc18Asm} from "../src/SphincsWcFc18Asm.sol";
import {SphincsWcPfp18} from "../src/SphincsWcPfp18.sol";
import {SphincsWcPfp18Asm} from "../src/SphincsWcPfp18Asm.sol";
import {SphincsWcPfp27} from "../src/SphincsWcPfp27.sol";
import {SphincsWcPfp27Asm} from "../src/SphincsWcPfp27Asm.sol";

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
        SphincsWcFc18 sol = new SphincsWcFc18(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C2 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        // Assembly verification
        SphincsWcFc18Asm asm_ = new SphincsWcFc18Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C2 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);

        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }

    // ================================================================
    //  Contract 1: W+C + P+FP (h=18, d=2) — 3704 bytes
    // ================================================================

    function test_C1_E2E() public {
        bytes32 message = keccak256("e2e_c1");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 1 (W+C + PORS+FP h=18)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c1", message);
        console.log("  Sig length: %d bytes", sig.length);

        SphincsWcPfp18 sol = new SphincsWcPfp18(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C1 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        SphincsWcPfp18Asm asm_ = new SphincsWcPfp18Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C1 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);
        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }

    // ================================================================
    //  Contract 3: W+C + P+FP (h=27, d=3) — 3596 bytes
    // ================================================================

    function test_C3_E2E() public {
        bytes32 message = keccak256("e2e_c3");

        console.log("================================================================");
        console.log("  E2E VERIFICATION: Contract 3 (W+C + PORS+FP h=27)");
        console.log("================================================================");

        (bytes32 seed, bytes32 root, bytes memory sig) = _callSigner("c3", message);
        console.log("  Sig length: %d bytes", sig.length);

        SphincsWcPfp27 sol = new SphincsWcPfp27(seed, root);
        uint256 g1 = gasleft();
        bool solValid = sol.verify(message, sig);
        uint256 solGas = g1 - gasleft();
        assertTrue(solValid, "C3 Solidity verify FAILED");
        console.log("  Solidity: VERIFIED (gas: %d)", solGas);

        SphincsWcPfp27Asm asm_ = new SphincsWcPfp27Asm(seed, root);
        uint256 g2 = gasleft();
        bool asmValid = asm_.verify(message, sig);
        uint256 asmGas = g2 - gasleft();
        assertTrue(asmValid, "C3 Assembly verify FAILED");
        console.log("  Assembly: VERIFIED (gas: %d)", asmGas);
        console.log("  Speedup: %dx", solGas / asmGas);
        console.log("");
    }
}
