// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/SphincsAccountFactory.sol";

/// @title DeploySepolia - Deploy SphincsAccountFactory to Sepolia
/// @notice Run: forge script script/DeploySepolia.s.sol --rpc-url sepolia --broadcast --verify
contract DeploySepolia is Script {
    // EntryPoint v0.9.0
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        SphincsAccountFactory factory = new SphincsAccountFactory(
            IEntryPoint(ENTRYPOINT_V09)
        );

        console.log("Factory deployed at:", address(factory));
        console.log("EntryPoint:", ENTRYPOINT_V09);

        vm.stopBroadcast();
    }
}
