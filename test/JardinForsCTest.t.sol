// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinForsCVerifier.sol";

contract JardinForsCTest is Test {
    JardinForsCVerifier verifier;

    uint256 constant FORSC_SIG_LEN = 2565; // 2452 + 1 + 7*16

    function setUp() public {
        verifier = new JardinForsCVerifier();
    }

    function _sign(string memory qLeaf) internal returns (bytes32, bytes32, bytes memory) {
        string[] memory inputs = new string[](4);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_signer.py";
        inputs[2] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        inputs[3] = qLeaf;
        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (bytes32, bytes32, bytes));
    }

    /// @notice FORS+C verifier roundtrip: Python signer → Solidity verifier (q=1)
    function testJardinForsCVerifyQ1() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign("1");

        assertEq(sig.length, FORSC_SIG_LEN, "Sig should be constant 2565 bytes");

        bool valid = verifier.verifyForsC(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "JARDIN FORS+C signature (q=1) should be valid");

        uint256 gasBefore = gasleft();
        verifier.verifyForsC(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("JARDIN FORS+C verify gas (q=1)", gasUsed);
    }

    /// @notice FORS+C verifier roundtrip at a right-branching leaf (q=64)
    function testJardinForsCVerifyQ64() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign("64");

        assertEq(sig.length, FORSC_SIG_LEN, "Sig should be constant 2565 bytes");

        bool valid = verifier.verifyForsC(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "JARDIN FORS+C signature (q=64) should be valid");

        uint256 gasBefore = gasleft();
        verifier.verifyForsC(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("JARDIN FORS+C verify gas (q=64)", gasUsed);
    }

    /// @notice Reject tampered signature
    function testJardinForsCRejectTampered() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign("1");

        // Tamper: flip a byte in the FORS secret area
        sig[50] ^= 0xFF;

        try verifier.verifyForsC(pkSeed, pkRoot, message, sig) returns (bool valid) {
            assertFalse(valid, "Tampered signature should not verify");
        } catch {
            // Revert is also acceptable (forced-zero check, etc.)
        }
    }
}
