// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinForsCVerifier.sol";

contract JardinForsCTest is Test {
    JardinForsCVerifier verifier;

    function setUp() public {
        verifier = new JardinForsCVerifier();
    }

    /// @notice FORS+C verifier roundtrip: Python signer → Solidity verifier (q=1)
    function testJardinForsCVerifyQ1() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

        string[] memory inputs = new string[](5);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_signer.py";
        inputs[2] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        inputs[3] = "1";   // q_leaf = 1
        inputs[4] = "4";   // q_max = 4 (small tree for fast test)

        bytes memory result = vm.ffi(inputs);
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(result, (bytes32, bytes32, bytes));

        assertEq(sig.length, 2468, "Sig should be 2452 + 1*16 = 2468 bytes for q=1");

        bool valid = verifier.verifyForsCUnbalanced(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "JARDIN FORS+C signature (q=1) should be valid");

        uint256 gasBefore = gasleft();
        verifier.verifyForsCUnbalanced(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("JARDIN FORS+C verify gas (q=1)", gasUsed);
    }

    /// @notice FORS+C verifier roundtrip with q=2 (deeper unbalanced tree leaf)
    function testJardinForsCVerifyQ2() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

        string[] memory inputs = new string[](5);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_signer.py";
        inputs[2] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        inputs[3] = "2";   // q_leaf = 2
        inputs[4] = "4";   // q_max = 4

        bytes memory result = vm.ffi(inputs);
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(result, (bytes32, bytes32, bytes));

        assertEq(sig.length, 2484, "Sig should be 2452 + 2*16 = 2484 bytes for q=2");

        bool valid = verifier.verifyForsCUnbalanced(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "JARDIN FORS+C signature (q=2) should be valid");

        uint256 gasBefore = gasleft();
        verifier.verifyForsCUnbalanced(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("JARDIN FORS+C verify gas (q=2)", gasUsed);
    }

    /// @notice Reject tampered signature
    function testJardinForsCRejectTampered() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

        string[] memory inputs = new string[](5);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_signer.py";
        inputs[2] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        inputs[3] = "1";
        inputs[4] = "4";

        bytes memory result = vm.ffi(inputs);
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(result, (bytes32, bytes32, bytes));

        // Tamper: flip a byte in the FORS secret area
        sig[50] ^= 0xFF;

        // Should revert or return false
        try verifier.verifyForsCUnbalanced(pkSeed, pkRoot, message, sig) returns (bool valid) {
            assertFalse(valid, "Tampered signature should not verify");
        } catch {
            // Revert is also acceptable (forced-zero check, etc.)
        }
    }
}
