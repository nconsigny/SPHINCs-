// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SLH-DSA-SHA2-128-24-Diagnostic.sol";

contract DiagnosticTest is Test {
    function testTree0Trace() public {
        SLH_DSA_SHA2_128_24_Diagnostic d = new SLH_DSA_SHA2_128_24_Diagnostic();

        bytes32 MSG = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
        bytes32 SK  = 0x1111111111111111111111111111111111111111111111111111111111111111;

        string[] memory inputs = new string[](4);
        inputs[0] = ".venv/bin/python";
        inputs[1] = "script/slh_dsa_sha2_128_24_fast_signer.py";
        inputs[2] = vm.toString(SK);
        inputs[3] = vm.toString(MSG);
        bytes memory result = vm.ffi(inputs);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(result, (bytes32, bytes32, bytes));

        (bytes32 leaf, bytes32 c0, bytes32 c1, bytes32 c2, bytes32 c3, bytes32 c4, bytes32 r0) =
            d.forsTree0Trace(seed, root, MSG, sig);

        emit log_named_bytes32("leaf", leaf);
        emit log_named_bytes32("c0", c0);
        emit log_named_bytes32("c1", c1);
        emit log_named_bytes32("c2", c2);
        emit log_named_bytes32("c3", c3);
        emit log_named_bytes32("c4", c4);
        emit log_named_bytes32("r0", r0);
    }
}
