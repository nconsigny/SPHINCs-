// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/WotsOtsAccountFactory.sol";

/// @title DeployWotsSepolia
/// @notice Deploys WotsOtsAccountFactory to Sepolia.
/// @dev Run with: forge script script/DeployWotsSepolia.s.sol --rpc-url sepolia --broadcast
contract DeployWotsSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        WotsOtsAccountFactory factory = new WotsOtsAccountFactory(
            IEntryPoint(ENTRYPOINT_V09)
        );

        console.log("WotsOtsAccountFactory deployed at:", address(factory));
        console.log("EntryPoint:", ENTRYPOINT_V09);

        vm.stopBroadcast();
    }
}
