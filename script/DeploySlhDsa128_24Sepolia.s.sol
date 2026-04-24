// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/SLH-DSA-SHA2-128-24verifier.sol";
import "../src/SLH-DSA-keccak-128-24verifier.sol";

/// @title DeploySlhDsa128_24Sepolia — Deploy the SLH-DSA-*-128-24 verifiers
/// @notice Two stateless, pure verifiers. Parameters follow NIST SP 800-230 Table 1:
///         n=16, h=22, d=1, h'=22, a=24, k=6, w=4 (lgw=2), m=21, sig=3,856 B.
///         SHA-2 variant is FIPS 205 bit-exact (SHA-256 precompile).
///         Keccak variant is the JARDIN family twin (keccak opcode, 32-byte ADRS).
///
/// Run:
///   forge script script/DeploySlhDsa128_24Sepolia.s.sol \
///     --rpc-url sepolia --broadcast
///
/// Sepolia deployment (chain 11155111, block 10722308):
///   SHA-2-128-24 verifier  : 0x9Fe41769395BC9fefb7e0d340064ed29F4a4Af91
///     deploy tx            : 0x09be3c5984ed99a93f9c43881822d9937e1efa9b31aee0630f59fca814d90e15
///     sample verify tx     : 0x00fa6b37347e2bedf37429a74563b2c68502becdffe3257ebde90f63e165030a
///     on-chain verify gas  : 225,642   (top-level tx, 3,856-B calldata included)
///   Keccak-128-24 verifier : 0x2Ac9Ec4a2A062aFc1be718e77ec3300D087E6205
///     deploy tx            : 0x253aa6dc5c93a201abc7a5cfb4ce27cdeafb35e34fc69c23ef1daae0535c4c4a
///     sample verify tx     : 0x90d785a112fd0198b4506caf432632777aef43b00ceb648e864dcb119311fed4
///     on-chain verify gas  : 177,910   (top-level tx, 3,856-B calldata included)
contract DeploySlhDsa128_24Sepolia is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        SLH_DSA_SHA2_128_24_Verifier sha2 = new SLH_DSA_SHA2_128_24_Verifier();
        console.log("SLH-DSA-SHA2-128-24  Verifier:", address(sha2));

        SLH_DSA_Keccak_128_24_Verifier kec = new SLH_DSA_Keccak_128_24_Verifier();
        console.log("SLH-DSA-Keccak-128-24 Verifier:", address(kec));

        vm.stopBroadcast();
    }
}
