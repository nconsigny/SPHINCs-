// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/JardinSpxVerifier.sol";
import "../src/JardinForsCVerifier.sol";
import "../src/JardinAccountFactory.sol";

/// @title DeployJardineroVhSepolia — Deploy variable-h FORS+C verifier + sibling factory
/// @notice Deploys the SPX verifier (plain SPHINCS+, default registration path),
///         a variable-h FORS+C verifier, and a sibling factory. Accounts created
///         through this factory accept Type 2 signatures built against slots
///         with any h ∈ [2, 8].
///
/// Historical addresses (fixed-h=7, legacy T0-based) on Sepolia:
///   T0 Verifier      0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767
///   FORS+C Verifier  0x4833624a57E59D2f888890ae6B776933c5FF6C68 (fixed h=7)
///   Factory          0xA9a718873E092aAE8170534eeb1ee3615F9E95F0
contract DeployJardineroVhSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        JardinSpxVerifier spxVerifier = new JardinSpxVerifier();
        console.log("JARDIN SPX Verifier:", address(spxVerifier));

        JardinForsCVerifier forscVh = new JardinForsCVerifier();
        console.log("JARDIN FORS+C Vh Verifier:", address(forscVh));

        JardinAccountFactory factoryVh = new JardinAccountFactory(
            IEntryPoint(ENTRYPOINT_V09),
            address(spxVerifier),
            address(forscVh)
        );
        console.log("JARDIN Factory (Vh):", address(factoryVh));

        vm.stopBroadcast();
    }
}
