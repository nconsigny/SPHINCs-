// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SPHINCs-C12Asm.sol";

/// @notice Standalone verifier-only test for SPHINCs-C12Asm.sol — plain
///         SPHINCS+ (h=20, d=5, h'=4, a=7, k=20, w=8, l=45) with the JARDIN
///         32-byte ADRS convention.  The JARDIN hybrid-account integration
///         (where this verifier is referenced as JardinSpxVerifier) lives in
///         the separate nconsigny/JARDIN repo; this file only tests C12 itself.
contract SphincsC12Test is Test {
    SPHINCs_C12Asm verifier;

    bytes32 constant MSG = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
    bytes32 constant SK  = 0x1111111111111111111111111111111111111111111111111111111111111111;

    bytes32 cachedSeed;
    bytes32 cachedRoot;
    bytes cachedSig;

    function setUp() public {
        verifier = new SPHINCs_C12Asm();
        string[] memory inputs = new string[](4);
        inputs[0] = ".venv/bin/python";
        inputs[1] = "script/jardin_spx_signer.py";
        inputs[2] = vm.toString(SK);
        inputs[3] = vm.toString(MSG);
        bytes memory result = vm.ffi(inputs);
        (cachedSeed, cachedRoot, cachedSig) = abi.decode(result, (bytes32, bytes32, bytes));
    }

    function _verifySilent(bytes32 seed, bytes32 root, bytes32 msg_, bytes memory sig)
        internal view returns (bool ok)
    {
        (bool call_ok, bytes memory res) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, seed, root, msg_, sig)
        );
        if (!call_ok) return false;
        if (res.length < 32) return false;
        ok = abi.decode(res, (bool));
    }

    function testC12VerifyValid() public view {
        assertEq(cachedSig.length, 6512, "sig length");
        assertTrue(
            _verifySilent(cachedSeed, cachedRoot, MSG, cachedSig),
            "C12 signature should be valid"
        );
    }

    function testC12VerifyGas() public {
        uint256 gasBefore = gasleft();
        verifier.verify(cachedSeed, cachedRoot, MSG, cachedSig);
        emit log_named_uint("C12 verify gas", gasBefore - gasleft());
    }

    function testC12RejectsWrongMessage() public view {
        bytes32 wrongMsg = bytes32(uint256(MSG) ^ 1);
        assertFalse(_verifySilent(cachedSeed, cachedRoot, wrongMsg, cachedSig));
    }

    function testC12RejectsWrongRoot() public view {
        bytes32 wrongRoot = bytes32(uint256(cachedRoot) ^ (1 << 200));
        assertFalse(_verifySilent(cachedSeed, wrongRoot, MSG, cachedSig));
    }

    function testC12RejectsShortSig() public {
        bytes memory bad = new bytes(6511);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(cachedSeed, cachedRoot, MSG, bad);
    }
}
