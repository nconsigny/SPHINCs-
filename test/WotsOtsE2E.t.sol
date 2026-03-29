// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {WotsOtsAccount} from "../src/WotsOtsAccount.sol";
import {WotsOtsAccountFactory} from "../src/WotsOtsAccountFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title WotsOtsE2E — End-to-end tests + gas benchmarks for WOTS+C OTS account
/// @notice Uses Python FFI signer for valid signature generation.
///         Run: forge test --match-contract WotsOtsE2E -vv
contract WotsOtsE2E is Test {

    IEntryPoint constant EP = IEntryPoint(address(0xdead));

    // ================================================================
    //  FFI Helpers
    // ================================================================

    function _keygen(bytes32 entropy)
        internal
        returns (bytes32 pkSeed, bytes32 pkHash, bytes32 skSeed)
    {
        string[] memory cmd = new string[](4);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/wots_ots_signer.py";
        cmd[2] = "keygen";
        cmd[3] = vm.toString(entropy);

        bytes memory result = vm.ffi(cmd);
        (pkSeed, pkHash, skSeed) = abi.decode(result, (bytes32, bytes32, bytes32));
    }

    function _sign(bytes32 entropy, bytes32 message)
        internal
        returns (bytes32 pkSeed, bytes32 pkHash, bytes memory sig)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/wots_ots_signer.py";
        cmd[2] = "sign";
        cmd[3] = vm.toString(entropy);
        cmd[4] = vm.toString(message);

        bytes memory result = vm.ffi(cmd);
        (pkSeed, pkHash, sig) = abi.decode(result, (bytes32, bytes32, bytes));
    }

    /// @dev Build a minimal PackedUserOperation for testing _validateSignature
    function _makeUserOp(bytes memory sig) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    // ================================================================
    //  Deploy helper: keygen + deploy + sign in one shot
    // ================================================================

    function _deploy(bytes32 entropy, bytes32 message)
        internal
        returns (WotsOtsAccount account, bytes memory sig, bytes32 msgHash)
    {
        msgHash = message;

        // Keygen
        (bytes32 pkSeed, bytes32 pkHash,) = _keygen(entropy);

        // Deploy account (mock entrypoint)
        account = new WotsOtsAccount(EP, pkSeed, pkHash);
        vm.deal(address(account), 1 ether);

        // Sign (stateless: rederives keys from entropy)
        (,, sig) = _sign(entropy, message);
    }

    // ================================================================
    //  Tests
    // ================================================================

    /// @notice Valid signature is accepted, key marked as used
    function test_ValidSignature() public {
        bytes32 entropy = keccak256("test_valid");
        bytes32 message = keccak256("hello_wots_ots");

        (WotsOtsAccount account, bytes memory sig, bytes32 msgHash) = _deploy(entropy, message);

        console.log("================================================================");
        console.log("  WOTS+C OTS: Valid Signature Test");
        console.log("================================================================");
        console.log("  Sig length: %d bytes", sig.length);

        vm.prank(address(EP));
        PackedUserOperation memory userOp = _makeUserOp(sig);
        uint256 g1 = gasleft();
        uint256 result = account.validateUserOp(userOp, msgHash, 0);
        uint256 gasUsed = g1 - gasleft();

        assertEq(result, 0, "Valid signature should return SUCCESS (0)");
        assertTrue(account.isUsed(), "Key should be marked as used");
        console.log("  Result: VALID");
        console.log("  Gas (validateUserOp): %d", gasUsed);
        console.log("");
    }

    /// @notice Second use of same key must be rejected
    function test_RejectAfterUse() public {
        bytes32 entropy = keccak256("test_reuse");
        bytes32 message = keccak256("reuse_msg");

        (WotsOtsAccount account, bytes memory sig, bytes32 msgHash) = _deploy(entropy, message);

        // First use — should succeed
        vm.prank(address(EP));
        uint256 r1 = account.validateUserOp(_makeUserOp(sig), msgHash, 0);
        assertEq(r1, 0, "First use should succeed");
        assertTrue(account.isUsed(), "Should be used after first sig");

        // Second use — must fail
        vm.prank(address(EP));
        uint256 r2 = account.validateUserOp(_makeUserOp(sig), msgHash, 0);
        assertEq(r2, 1, "Second use MUST return FAILED (1)");

        console.log("  RejectAfterUse: PASSED (second call returned FAILED)");
    }

    /// @notice Invalid signature is rejected, state unchanged
    function test_RejectInvalidSig() public {
        bytes32 entropy = keccak256("test_invalid");
        bytes32 message = keccak256("invalid_msg");

        (bytes32 pkSeed, bytes32 pkHash,) = _keygen(entropy);
        WotsOtsAccount account = new WotsOtsAccount(EP, pkSeed, pkHash);

        // Craft garbage sig of correct length
        bytes memory badSig = new bytes(516);
        for (uint256 i = 0; i < 516; i++) {
            badSig[i] = bytes1(uint8(i & 0xFF));
        }

        vm.prank(address(EP));
        uint256 result = account.validateUserOp(_makeUserOp(badSig), message, 0);
        assertEq(result, 1, "Invalid sig should return FAILED");
        assertFalse(account.isUsed(), "State must not change on invalid sig");

        console.log("  RejectInvalidSig: PASSED (state unchanged)");
    }

    /// @notice Valid sig for msg A fails against msg B
    function test_RejectWrongMessage() public {
        bytes32 entropy = keccak256("test_wrong_msg");
        bytes32 msgA = keccak256("message_A");
        bytes32 msgB = keccak256("message_B");

        // Keygen + sign for msgA (stateless: rederives keys from entropy)
        (bytes32 pkSeed, bytes32 pkHash,) = _keygen(entropy);
        (,, bytes memory sigA) = _sign(entropy, msgA);

        // Deploy account with the same keys
        WotsOtsAccount account = new WotsOtsAccount(EP, pkSeed, pkHash);

        // Verify sigA against msgB — must fail
        vm.prank(address(EP));
        uint256 result = account.validateUserOp(_makeUserOp(sigA), msgB, 0);
        assertEq(result, 1, "Sig for wrong message should fail");
        assertFalse(account.isUsed(), "State must not change");

        console.log("  RejectWrongMessage: PASSED");
    }

    /// @notice Wrong signature length is rejected
    function test_RejectBadSigLength() public {
        bytes32 entropy = keccak256("test_bad_len");
        (bytes32 pkSeed, bytes32 pkHash,) = _keygen(entropy);
        WotsOtsAccount account = new WotsOtsAccount(EP, pkSeed, pkHash);

        // Too short
        bytes memory shortSig = new bytes(500);
        vm.prank(address(EP));
        uint256 r1 = account.validateUserOp(_makeUserOp(shortSig), keccak256("x"), 0);
        assertEq(r1, 1, "Short sig should fail");

        // Too long
        bytes memory longSig = new bytes(600);
        vm.prank(address(EP));
        uint256 r2 = account.validateUserOp(_makeUserOp(longSig), keccak256("x"), 0);
        assertEq(r2, 1, "Long sig should fail");

        assertFalse(account.isUsed());
        console.log("  RejectBadSigLength: PASSED");
    }

    // ================================================================
    //  Gas Benchmark
    // ================================================================

    /// @notice Detailed gas measurement for WOTS+C OTS verification
    function test_GasBenchmark() public {
        bytes32 entropy = keccak256("bench");
        bytes32 message = keccak256("benchmark_msg");

        (WotsOtsAccount account, bytes memory sig, bytes32 msgHash) = _deploy(entropy, message);

        console.log("================================================================");
        console.log("  WOTS+C OTS Gas Benchmark");
        console.log("================================================================");
        console.log("  Parameters: w=16, n=128, l=32, targetSum=240");
        console.log("  Signature size: %d bytes", sig.length);
        console.log("");

        // Measure validateUserOp (includes 4337 overhead)
        vm.prank(address(EP));
        uint256 g1 = gasleft();
        uint256 result = account.validateUserOp(_makeUserOp(sig), msgHash, 0);
        uint256 totalGas = g1 - gasleft();

        assertEq(result, 0, "Benchmark sig must be valid");

        // Calldata analysis
        uint256 sigNz = 0;
        for (uint256 i = 0; i < sig.length; i++) {
            if (sig[i] != 0) sigNz++;
        }
        uint256 sigZ = sig.length - sigNz;
        uint256 calldataStd = sigNz * 16 + sigZ * 4;
        uint256 calldataFloor = sigNz * 60 + sigZ * 15;

        console.log("  Verification gas (validateUserOp): %d", totalGas);
        console.log("");
        console.log("  Calldata analysis (sig only):");
        console.log("    Non-zero bytes: %d", sigNz);
        console.log("    Zero bytes:     %d", sigZ);
        console.log("    Standard cost:  %d gas", calldataStd);
        console.log("    EIP-7623 floor: %d gas", calldataFloor);
        console.log("");
        console.log("  Estimated full tx gas:");
        console.log("    Standard: %d (21000 base + %d cd + %d exec)",
            21000 + calldataStd + totalGas, calldataStd, totalGas);
        console.log("    Floor:    %d (21000 base + %d floor)",
            21000 + calldataFloor, calldataFloor);
        console.log("================================================================");
    }

    /// @notice Successful validation still pays prefund to the EntryPoint.
    function test_ValidateUserOpPaysPrefund() public {
        bytes32 entropy = keccak256("prefund");
        bytes32 message = keccak256("prefund_msg");

        (WotsOtsAccount account, bytes memory sig, bytes32 msgHash) = _deploy(entropy, message);

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = address(EP).balance;
        uint256 accountBalanceBefore = address(account).balance;

        vm.prank(address(EP));
        uint256 result = account.validateUserOp(_makeUserOp(sig), msgHash, prefund);

        assertEq(result, 0, "Valid signature should still succeed");
        assertEq(address(EP).balance, epBalanceBefore + prefund, "EntryPoint should receive prefund");
        assertEq(address(account).balance, accountBalanceBefore - prefund, "Account should pay prefund");
    }

    // ================================================================
    //  Factory Test
    // ================================================================

    function test_Factory() public {
        WotsOtsAccountFactory factory = new WotsOtsAccountFactory(EP);

        bytes32 entropy = keccak256("factory_test");
        (bytes32 pkSeed, bytes32 pkHash,) = _keygen(entropy);

        // Precompute address
        address predicted = factory.getAddress(pkSeed, pkHash);

        // Deploy
        WotsOtsAccount account = factory.createAccount(pkSeed, pkHash);

        assertEq(address(account), predicted, "CREATE2 address mismatch");
        assertEq(account.pkSeed(), pkSeed, "pkSeed mismatch");
        assertFalse(account.isUsed(), "Fresh account should not be used");

        console.log("  Factory: deployed at %s", vm.toString(address(account)));
    }
}
