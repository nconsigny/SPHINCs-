// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SPHINCs-C8Asm.sol";

contract SphincsC8Test is Test {
    SphincsC8Asm verifier;

    function setUp() public {
        verifier = new SphincsC8Asm();
    }

    function testC8VerifyFFI() public {
        // Sign a test message using Python signer
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

        string[] memory inputs = new string[](4);
        inputs[0] = "python3";
        inputs[1] = "script/signer.py";
        inputs[2] = "c8";
        inputs[3] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        bytes memory result = vm.ffi(inputs);

        // Decode: seed(32) || root(32) || offset(32) || length(32) || sig_padded
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(result, (bytes32, bytes32, bytes));

        // Verify
        bool valid = verifier.verify(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "C8 signature should be valid");

        // Gas measurement
        uint256 gasBefore = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("C8 verify gas", gasUsed);
    }
}
