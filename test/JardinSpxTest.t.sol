// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinSpxVerifier.sol";
import "../src/JardinForsCVerifier.sol";
import "../src/JardinAccountFactory.sol";
import "../src/JardinAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

contract JardinSpxTest is Test {
    JardinSpxVerifier verifier;

    bytes32 constant MSG = 0xdeadbeef00000000000000000000000000000000000000000000000000000000;
    bytes32 constant SK  = 0x1111111111111111111111111111111111111111111111111111111111111111;

    bytes32 cachedSeed;
    bytes32 cachedRoot;
    bytes cachedSig;

    function setUp() public {
        verifier = new JardinSpxVerifier();

        // Cache a valid signature once per suite to avoid repeated FFI spawns.
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

    function testSpxVerifyValid() public view {
        assertEq(cachedSig.length, 6512, "sig length");
        assertTrue(
            _verifySilent(cachedSeed, cachedRoot, MSG, cachedSig),
            "SPX signature should be valid"
        );
    }

    function testSpxVerifyGas() public {
        string[] memory inputs = new string[](4);
        inputs[0] = ".venv/bin/python";
        inputs[1] = "script/jardin_spx_signer.py";
        inputs[2] = vm.toString(SK);
        inputs[3] = vm.toString(MSG);
        (bytes32 seed, bytes32 root, bytes memory sig) =
            abi.decode(vm.ffi(inputs), (bytes32, bytes32, bytes));

        uint256 gasBefore = gasleft();
        verifier.verify(seed, root, MSG, sig);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("SPX verify gas (memory sig)", gasUsed);
    }

    function testSpxRejectsWrongMessage() public view {
        bytes32 wrongMsg = bytes32(uint256(MSG) ^ 1);
        assertFalse(_verifySilent(cachedSeed, cachedRoot, wrongMsg, cachedSig));
    }

    function testSpxRejectsWrongRoot() public view {
        bytes32 wrongRoot = bytes32(uint256(cachedRoot) ^ (1 << 200));
        assertFalse(_verifySilent(cachedSeed, wrongRoot, MSG, cachedSig));
    }

    function testSpxRejectsWrongSeed() public view {
        bytes32 wrongSeed = bytes32(uint256(cachedSeed) ^ (1 << 200));
        assertFalse(_verifySilent(wrongSeed, cachedRoot, MSG, cachedSig));
    }

    function testSpxRejectsShortSig() public {
        bytes memory bad = new bytes(6511);
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verify(cachedSeed, cachedRoot, MSG, bad);
    }

    function testSpxRejectsLongSig() public {
        bytes memory bad = new bytes(6513);
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

    function testSpxRejectsTamperedR()           public view { _assertTamperFails(8); }
    function testSpxRejectsTamperedFORSSecret()  public view { _assertTamperFails(32 + 8 * 128); }   // inside sk_8
    function testSpxRejectsTamperedFORSAuth()    public view { _assertTamperFails(32 + 16 + 12); }   // inside auth_0 level 0
    function testSpxRejectsTamperedWOTSChain()   public view { _assertTamperFails(2592 + 100); }     // layer-0 WOTS
    function testSpxRejectsTamperedXMSSAuth()    public view { _assertTamperFails(2592 + 720 + 8); } // layer-0 XMSS auth

    function testFactoryDeploysWithSpx() public {
        JardinForsCVerifier forsc = new JardinForsCVerifier();
        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(address(0xdead)), address(verifier), address(forsc)
        );

        address ecdsaOwner = address(0xBEEF);
        address predicted  = factory.getAddress(ecdsaOwner, cachedSeed, cachedRoot);
        JardinAccount account = factory.createAccount(ecdsaOwner, cachedSeed, cachedRoot);

        assertEq(address(account), predicted, "CREATE2 address mismatch");
        assertEq(account.owner(), ecdsaOwner);
        assertEq(account.spxVerifier(), address(verifier));
        assertEq(account.forscVerifier(), address(forsc));
        assertEq(account.spxPkSeed(), cachedSeed);
        assertEq(account.spxPkRoot(), cachedRoot);
        assertEq(account.c11Verifier(), address(0), "C11 recovery must be unset on deploy");

        // Confirm the verifier address stored in the account actually accepts
        // the cached signature (end-to-end: factory → account → SPX verifier).
        bool ok = JardinSpxVerifier(account.spxVerifier()).verify(
            account.spxPkSeed(), account.spxPkRoot(), MSG, cachedSig
        );
        assertTrue(ok, "factory-deployed account must validate the cached sig");
    }

    function testRotateSpxKeys() public {
        JardinForsCVerifier forsc = new JardinForsCVerifier();
        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(address(0xdead)), address(verifier), address(forsc)
        );
        JardinAccount account = factory.createAccount(
            address(0xBEEF), cachedSeed, cachedRoot
        );

        bytes32 newSeed = bytes32(uint256(0x1234));
        bytes32 newRoot = bytes32(uint256(0x5678));
        vm.prank(address(account));
        account.rotateSpxKeys(newSeed, newRoot);
        assertEq(account.spxPkSeed(), newSeed);
        assertEq(account.spxPkRoot(), newRoot);

        // Non-self rotation must revert.
        vm.prank(address(0xBEEF));
        vm.expectRevert(JardinAccount.NotEntryPoint.selector);
        account.rotateSpxKeys(bytes32(0), bytes32(0));
    }
}
