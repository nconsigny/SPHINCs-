// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SPHINCs-C11Asm.sol";

contract SphincsC11Test is Test {
    SphincsC11Asm verifier;

    function setUp() public {
        verifier = new SphincsC11Asm();
    }

    function testC11VerifyFFI() public {
        bytes32 message = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

        string[] memory inputs = new string[](4);
        inputs[0] = "python3";
        inputs[1] = "script/signer.py";
        inputs[2] = "c11";
        inputs[3] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        bytes memory result = vm.ffi(inputs);
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(result, (bytes32, bytes32, bytes));

        bool valid = verifier.verify(pkSeed, pkRoot, message, sig);
        assertTrue(valid, "C11 signature should be valid");

        uint256 gasBefore = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("C11 verify gas", gasUsed);
    }
}
