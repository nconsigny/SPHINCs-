// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SLH-DSA-SHA2-128-24verifier.sol";

/// @notice End-to-end test of the FIPS 205 SLH-DSA-SHA2-128-24 verifier
///         against real signatures produced by our forked sphincsplus C
///         binary (signers/sphincsplus-128-24/slhdsa-sha2-128-24).
///
///         The `script/slh_dsa_sha2_128_24_fast_signer.py` wrapper caches
///         fixture signatures to disk (signers/sphincsplus-128-24/.cache/)
///         so subsequent test runs don't pay the ~1-3 min C-signer cost.
contract SLH_DSA_SHA2_128_24_Test is Test {
    SLH_DSA_SHA2_128_24_Verifier verifier;

    bytes32 constant MSG = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
    bytes32 constant SK  = 0x1111111111111111111111111111111111111111111111111111111111111111;

    bytes32 cachedSeed;
    bytes32 cachedRoot;
    bytes cachedSig;

    function setUp() public {
        verifier = new SLH_DSA_SHA2_128_24_Verifier();

        // One-shot: call the wrapper, receive ABI-encoded (seed, root, sig).
        string[] memory inputs = new string[](4);
        inputs[0] = ".venv/bin/python";
        inputs[1] = "script/slh_dsa_sha2_128_24_fast_signer.py";
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

    function testValidSignature() public view {
        assertEq(cachedSig.length, 3856, "sig length");
        assertTrue(
            _verifySilent(cachedSeed, cachedRoot, MSG, cachedSig),
            "SLH-DSA-SHA2-128-24 signature should verify"
        );
    }

    function testVerifyGas() public {
        uint256 gasBefore = gasleft();
        verifier.verify(cachedSeed, cachedRoot, MSG, cachedSig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("SLH-DSA-SHA2-128-24 verify gas", gasUsed);
    }

    function testRejectsWrongMessage() public view {
        bytes32 wrongMsg = bytes32(uint256(MSG) ^ 1);
        assertFalse(_verifySilent(cachedSeed, cachedRoot, wrongMsg, cachedSig));
    }

    function testRejectsWrongRoot() public view {
        bytes32 wrongRoot = bytes32(uint256(cachedRoot) ^ (1 << 200));
        assertFalse(_verifySilent(cachedSeed, wrongRoot, MSG, cachedSig));
    }

    function testRejectsShortSig() public {
        bytes memory bad = new bytes(3855);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(cachedSeed, cachedRoot, MSG, bad);
    }

    function _assertTamperFails(uint256 offset) internal view {
        bytes memory tampered = new bytes(cachedSig.length);
        for (uint256 i = 0; i < cachedSig.length; i++) tampered[i] = cachedSig[i];
        tampered[offset] = bytes1(uint8(tampered[offset]) ^ 0x01);
        assertFalse(
            _verifySilent(cachedSeed, cachedRoot, MSG, tampered),
            "tampered sig must not verify"
        );
    }

    function testRejectsTamperedR()          public view { _assertTamperFails(8); }
    function testRejectsTamperedFORSSecret() public view { _assertTamperFails(16 + 2 * 400); } // sk of tree 2
    function testRejectsTamperedWOTSChain()  public view { _assertTamperFails(16 + 2400 + 100); } // WOTS chain
    function testRejectsTamperedXMSSAuth()   public view { _assertTamperFails(16 + 2400 + 1088 + 16); } // XMSS auth
}
