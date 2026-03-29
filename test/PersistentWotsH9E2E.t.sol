// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {PersistentWotsAccount} from "../src/PersistentWotsAccount.sol";
import {PersistentWotsAccountFactory} from "../src/PersistentWotsAccountFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract PersistentWotsH9E2E is Test {
    IEntryPoint constant EP = IEntryPoint(address(0xdead));

    function _keygen(bytes32 entropy) internal returns (bytes32 pkSeed, bytes32 pkRoot) {
        string[] memory cmd = new string[](4);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/persistent_wots_h9_signer.py";
        cmd[2] = "keygen";
        cmd[3] = vm.toString(entropy);

        bytes memory result = vm.ffi(cmd);
        (pkSeed, pkRoot) = abi.decode(result, (bytes32, bytes32));
    }

    function _sign(
        bytes32 entropy,
        uint256 leafIndex,
        bytes32 message
    ) internal returns (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) {
        string[] memory cmd = new string[](6);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/persistent_wots_h9_signer.py";
        cmd[2] = "sign";
        cmd[3] = vm.toString(entropy);
        cmd[4] = vm.toString(leafIndex);
        cmd[5] = vm.toString(message);

        bytes memory result = vm.ffi(cmd);
        (pkSeed, pkRoot, sig) = abi.decode(result, (bytes32, bytes32, bytes));
    }

    function _makeUserOp(bytes memory sig, uint256 nonce) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(0),
            nonce: nonce,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    function _deploy(bytes32 entropy) internal returns (PersistentWotsAccount account) {
        (bytes32 pkSeed, bytes32 pkRoot) = _keygen(entropy);
        account = new PersistentWotsAccount(EP, pkSeed, pkRoot);
        vm.deal(address(account), 1 ether);
    }

    function test_TwoLeavesValidate() public {
        bytes32 entropy = keccak256("persistent_h9_valid");
        PersistentWotsAccount account = _deploy(entropy);

        (,, bytes memory sig0) = _sign(entropy, 0, keccak256("msg0"));
        (,, bytes memory sig1) = _sign(entropy, 1, keccak256("msg1"));

        vm.prank(address(EP));
        uint256 r0 = account.validateUserOp(_makeUserOp(sig0, 0), keccak256("msg0"), 0);
        vm.prank(address(EP));
        uint256 r1 = account.validateUserOp(_makeUserOp(sig1, 1), keccak256("msg1"), 0);

        assertEq(r0, 0, "leaf 0 should validate");
        assertEq(r1, 0, "leaf 1 should validate");
    }

    function test_WrongNonceFails() public {
        bytes32 entropy = keccak256("persistent_h9_wrong_nonce");
        PersistentWotsAccount account = _deploy(entropy);
        (,, bytes memory sig0) = _sign(entropy, 0, keccak256("wrong_nonce"));

        vm.prank(address(EP));
        uint256 result = account.validateUserOp(_makeUserOp(sig0, 1), keccak256("wrong_nonce"), 0);
        assertEq(result, 1, "leaf 0 signature must fail at nonce 1");
    }

    function test_NonceOutOfRangeReverts() public {
        bytes32 entropy = keccak256("persistent_h9_range");
        PersistentWotsAccount account = _deploy(entropy);
        (,, bytes memory sig0) = _sign(entropy, 0, keccak256("range"));

        vm.expectRevert("PersistentWots: nonce out of range");
        vm.prank(address(EP));
        account.validateUserOp(_makeUserOp(sig0, 512), keccak256("range"), 0);
    }

    function test_ValidateUserOpPaysPrefund() public {
        bytes32 entropy = keccak256("persistent_h9_prefund");
        PersistentWotsAccount account = _deploy(entropy);
        bytes32 message = keccak256("prefund");
        (,, bytes memory sig0) = _sign(entropy, 0, message);

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = address(EP).balance;
        uint256 accountBalanceBefore = address(account).balance;

        vm.prank(address(EP));
        uint256 result = account.validateUserOp(_makeUserOp(sig0, 0), message, prefund);

        assertEq(result, 0, "signature should validate");
        assertEq(address(EP).balance, epBalanceBefore + prefund, "EntryPoint should receive prefund");
        assertEq(address(account).balance, accountBalanceBefore - prefund, "account should pay prefund");
    }

    function test_Factory() public {
        PersistentWotsAccountFactory factory = new PersistentWotsAccountFactory(EP);
        bytes32 entropy = keccak256("persistent_h9_factory");
        (bytes32 pkSeed, bytes32 pkRoot) = _keygen(entropy);

        address predicted = factory.getAddress(pkSeed, pkRoot);
        PersistentWotsAccount account = factory.createAccount(pkSeed, pkRoot);

        assertEq(address(account), predicted, "CREATE2 address mismatch");
        assertEq(account.pkSeed(), pkSeed, "pkSeed mismatch");
        assertEq(account.pkRoot(), pkRoot, "pkRoot mismatch");
    }

    function test_GasBenchmark() public {
        bytes32 entropy = keccak256("persistent_h9_bench");
        PersistentWotsAccount account = _deploy(entropy);
        bytes32 message = keccak256("bench");
        (,, bytes memory sig0) = _sign(entropy, 0, message);

        vm.prank(address(EP));
        uint256 g0 = gasleft();
        uint256 result = account.validateUserOp(_makeUserOp(sig0, 0), message, 0);
        uint256 gasUsed = g0 - gasleft();

        assertEq(result, 0, "benchmark sig must validate");
        console.log("Persistent h=9 WOTS+C validateUserOp gas: %d", gasUsed);
        console.log("Persistent h=9 WOTS+C signature bytes: %d", sig0.length);
    }
}
