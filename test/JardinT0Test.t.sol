// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinT0Verifier.sol";

contract JardinT0Test is Test {
    JardinT0Verifier verifier;

    bytes32 constant MSG = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
    bytes32 constant SK  = 0x1111111111111111111111111111111111111111111111111111111111111111;

    bytes32 cachedSeed;
    bytes32 cachedRoot;
    bytes cachedSig;

    function setUp() public {
        verifier = new JardinT0Verifier();

        // Cache a valid signature once per suite to avoid repeated FFI spawns.
        string[] memory inputs = new string[](4);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_t0_signer.py";
        inputs[2] = vm.toString(SK);
        inputs[3] = vm.toString(MSG);
        bytes memory result = vm.ffi(inputs);
        (cachedSeed, cachedRoot, cachedSig) = abi.decode(result, (bytes32, bytes32, bytes));
    }

    /// @dev Wrap verify so we can observe both revert and `false` as failure.
    function _verifySilent(bytes32 seed, bytes32 root, bytes32 msg_, bytes memory sig)
        internal
        view
        returns (bool ok)
    {
        (bool call_ok, bytes memory res) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, seed, root, msg_, sig)
        );
        if (!call_ok) return false;
        if (res.length < 32) return false;
        ok = abi.decode(res, (bool));
    }

    function testT0VerifyValid() public view {
        assertEq(cachedSig.length, 8220, "sig length");
        assertTrue(
            _verifySilent(cachedSeed, cachedRoot, MSG, cachedSig),
            "T0 signature should be valid"
        );
    }

    function testT0VerifyGas() public {
        // Reload from FFI so the sig lives in memory, not storage —
        // otherwise SLOADs from the cached-storage path dominate the reading.
        string[] memory inputs = new string[](4);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_t0_signer.py";
        inputs[2] = vm.toString(SK);
        inputs[3] = vm.toString(MSG);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(vm.ffi(inputs), (bytes32, bytes32, bytes));

        uint256 gasBefore = gasleft();
        verifier.verify(seed, root, MSG, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("T0 verify gas (memory sig)", gasUsed);
    }

    function testT0RejectsWrongMessage() public view {
        bytes32 wrongMsg = bytes32(uint256(MSG) ^ 1);
        assertFalse(_verifySilent(cachedSeed, cachedRoot, wrongMsg, cachedSig));
    }

    function testT0RejectsWrongRoot() public view {
        bytes32 wrongRoot = bytes32(uint256(cachedRoot) ^ (1 << 200));
        assertFalse(_verifySilent(cachedSeed, wrongRoot, MSG, cachedSig));
    }

    function testT0RejectsWrongSeed() public view {
        bytes32 wrongSeed = bytes32(uint256(cachedSeed) ^ (1 << 200));
        assertFalse(_verifySilent(wrongSeed, cachedRoot, MSG, cachedSig));
    }

    function testT0RejectsShortSig() public {
        bytes memory bad = new bytes(8219);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(cachedSeed, cachedRoot, MSG, bad);
    }

    function testT0RejectsLongSig() public {
        bytes memory bad = new bytes(8221);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(cachedSeed, cachedRoot, MSG, bad);
    }

    /// @dev Flip one byte at the given offset and confirm the sig no longer verifies.
    ///      The verifier may revert (digit-sum mismatch) or return false (root mismatch);
    ///      both are acceptable failures, captured by `_verifySilent`.
    function _assertTamperFails(uint256 offset) internal view {
        bytes memory tampered = new bytes(cachedSig.length);
        for (uint256 i = 0; i < cachedSig.length; i++) tampered[i] = cachedSig[i];
        tampered[offset] = bytes1(uint8(tampered[offset]) ^ 0x01);
        assertFalse(
            _verifySilent(cachedSeed, cachedRoot, MSG, tampered),
            "tampered sig must not verify"
        );
    }

    function testT0RejectsTamperedR() public view        { _assertTamperFails(8); }
    function testT0RejectsTamperedFORSSecret() public view { _assertTamperFails(16 + 8 * 16); } // inside secret_8
    function testT0RejectsTamperedFORSAuth() public view   { _assertTamperFails(640 + 12); }    // inside auth_0 level 0
    function testT0RejectsTamperedHTCounter() public view  { _assertTamperFails(4384 + 1); }    // layer-0 counter
    function testT0RejectsTamperedWOTSChain() public view  { _assertTamperFails(4384 + 4 + 100); } // layer-0 wots
    function testT0RejectsTamperedXMSSAuth() public view   { _assertTamperFails(4384 + 4 + 512 + 8); } // layer-0 xmss auth

    // T0 is no longer the default slot-registration path in JardinAccount
    // (replaced by plain-SPX). T0 verifier tests above still exercise the
    // standalone verifier contract; factory/account integration is covered
    // in test/JardinSpxTest.t.sol.
}
