// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";
import "../src/PersistentWotsAccount.sol";

contract SendPersistentWotsUsdcSepolia is Script {
    uint256 constant MAX_LEAVES = 512;
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
    address constant TEST_USDC = 0xbe72E441BF55620febc26715db68d3494213D8Cb;
    address constant RECIPIENT = 0x50EBa181bd0770bD145dC543617e457666B017fD;
    uint256 constant AMOUNT = 2 ether;

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address beneficiary = vm.addr(privateKey);

        bytes32 entropy = vm.envBytes32("PERSISTENT_WOTS_ENTROPY");
        address account = vm.envAddress("PERSISTENT_WOTS_ACCOUNT");

        IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT_V09);
        uint256 nonce = entryPoint.getNonce(account, 0);
        require(nonce < MAX_LEAVES, "nonce exhausted");

        bytes memory tokenCall = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT, AMOUNT);
        bytes memory callData = abi.encodeWithSignature("execute(address,uint256,bytes)", TEST_USDC, 0, tokenCall);

        uint256 verificationGasLimit = 500_000;
        uint256 callGasLimit = 150_000;
        uint256 maxPriorityFeePerGas = 1 gwei;
        uint256 maxFeePerGas = block.basefee * 2 + maxPriorityFeePerGas;

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((verificationGasLimit << 128) | callGasLimit),
            preVerificationGas: 120_000,
            gasFees: bytes32((maxPriorityFeePerGas << 128) | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        string[] memory cmd = new string[](6);
        cmd[0] = "/usr/bin/python3";
        cmd[1] = "script/persistent_wots_h9_signer.py";
        cmd[2] = "sign";
        cmd[3] = vm.toString(entropy);
        cmd[4] = vm.toString(nonce);
        cmd[5] = vm.toString(userOpHash);

        bytes memory ffiResult = vm.ffi(cmd);
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = abi.decode(ffiResult, (bytes32, bytes32, bytes));

        PersistentWotsAccount wallet = PersistentWotsAccount(payable(account));
        require(wallet.pkSeed() == pkSeed, "seed mismatch");
        require(wallet.pkRoot() == pkRoot, "root mismatch");

        userOp.signature = sig;

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        console.log("Persistent WOTS account:", account);
        console.log("Nonce:", nonce);
        console.log("UserOp hash:");
        console.logBytes32(userOpHash);
        console.log("Recipient:", RECIPIENT);
        console.log("Amount:", AMOUNT);

        vm.startBroadcast(privateKey);
        entryPoint.handleOps(ops, payable(beneficiary));
        vm.stopBroadcast();
    }

}
