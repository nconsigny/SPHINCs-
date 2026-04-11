// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/JardinForsCVerifier.sol";
import "../src/JardinAccountFactory.sol";

/// @title DeployJardinSepolia - Deploy JARDÍN verifier + factory on Sepolia
/// @notice Run: forge script script/DeployJardinSepolia.s.sol --rpc-url sepolia --broadcast
contract DeployJardinSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
    address constant C11_VERIFIER   = 0xC25ef566884DC36649c3618EEDF66d715427Fd74;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        // 1. Deploy JARDÍN FORS+C verifier
        JardinForsCVerifier forscVerifier = new JardinForsCVerifier();
        console.log("JARDIN FORS+C Verifier:", address(forscVerifier));

        // 2. Deploy hybrid ECDSA + JARDÍN account factory
        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(ENTRYPOINT_V09),
            C11_VERIFIER,
            address(forscVerifier)
        );
        console.log("JARDIN Factory (hybrid):", address(factory));

        vm.stopBroadcast();
    }
}
