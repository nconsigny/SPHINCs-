// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/JardinT0Verifier.sol";
import "../src/JardinForsCVerifier.sol";
import "../src/JardinAccountFactory.sol";

/// @title DeployJardineroSepolia — Deploy JARDINERO stack on Sepolia
/// @notice T0 verifier (primary) + FORS+C verifier (compact) + factory.
///         C11 remains available as optional recovery — attached per-account
///         via JardinAccount.attachC11Recovery, not at factory level.
///
/// Run: forge script script/DeployJardineroSepolia.s.sol --rpc-url sepolia --broadcast
contract DeployJardineroSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        JardinT0Verifier t0Verifier = new JardinT0Verifier();
        console.log("JARDINERO T0 Verifier:", address(t0Verifier));

        JardinForsCVerifier forscVerifier = new JardinForsCVerifier();
        console.log("JARDIN FORS+C Verifier:", address(forscVerifier));

        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(ENTRYPOINT_V09),
            address(t0Verifier),
            address(forscVerifier)
        );
        console.log("JARDINERO Factory:", address(factory));

        vm.stopBroadcast();
    }
}
