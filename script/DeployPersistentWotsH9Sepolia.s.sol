// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/PersistentWotsAccountFactory.sol";

/// @title DeployPersistentWotsH9Sepolia
/// @notice Deploys the persistent h=9 WOTS+C factory to Sepolia.
contract DeployPersistentWotsH9Sepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        PersistentWotsAccountFactory factory = new PersistentWotsAccountFactory(IEntryPoint(ENTRYPOINT_V09));

        console.log("PersistentWotsAccountFactory deployed at:", address(factory));
        console.log("EntryPoint:", ENTRYPOINT_V09);

        vm.stopBroadcast();
    }
}
