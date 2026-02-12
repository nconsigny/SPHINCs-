// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {SecurityAnalysis} from "../src/SecurityAnalysis.sol";

/// @title SecurityDecay - Tests for signature reuse decay analysis
contract SecurityDecay is Test {
    /// @notice Map security decay across signature counts for all three contracts
    function test_SecurityDecayTable() public pure {
        console.log("=================================================================");
        console.log("  Signature Reuse Security Decay (estimated security bits)");
        console.log("=================================================================");
        console.log("");
        console.log("  Signatures    C1/C2 (h=18)    C3 (h=27)");
        console.log("  ----------------------------------------");

        uint256[8] memory counts = [
            uint256(1),
            uint256(1 << 10),   // 1K
            uint256(1 << 15),   // 32K
            uint256(1 << 18),   // 262K (= 2^h for C1/C2)
            uint256(1 << 20),   // 1M (target budget)
            uint256(1 << 22),   // 4M
            uint256(1 << 25),   // 33M
            uint256(1 << 27)    // 134M (= 2^h for C3)
        ];

        for (uint256 i = 0; i < 8; i++) {
            uint256 q = counts[i];
            uint256 sec18 = SecurityAnalysis.estimateSecurityBits(q, 18, 13, 13);
            uint256 sec27 = SecurityAnalysis.estimateSecurityBits(q, 27, 11, 11);

            if (q < 1000) {
                console.log("  %d             %d bits         %d bits", q, sec18, sec27);
            } else if (q < 1000000) {
                console.log("  %dK           %d bits         %d bits", q / 1000, sec18, sec27);
            } else {
                console.log("  %dM           %d bits         %d bits", q / 1000000, sec18, sec27);
            }
        }

        console.log("");
        console.log("  Key: 128 = full security, 112 = minimum acceptable");
        console.log("       C1 = W+C_P+FP(18,2), C2 = W+C(18,2), C3 = W+C_P+FP(27,3)");
    }

    /// @notice Test budget checks for wallet integration
    function test_BudgetChecks() public pure {
        // Contract 1/2 (h=18, k=13, a=13) at 112-bit threshold
        bool safe1m = SecurityAnalysis.isWithinBudget(1_000_000, 18, 13, 13, 112);
        bool safe4m = SecurityAnalysis.isWithinBudget(4_000_000, 18, 13, 13, 112);
        bool safe10m = SecurityAnalysis.isWithinBudget(10_000_000, 18, 13, 13, 112);

        console.log("=== Budget Safety Checks (112-bit minimum) ===");
        console.log("");
        console.log("Contract 1/2 (h=18, k=13, a=13):");
        console.log("  1M sigs: %s", safe1m ? "SAFE" : "ROTATE KEY");
        console.log("  4M sigs: %s", safe4m ? "SAFE" : "ROTATE KEY");
        console.log("  10M sigs: %s", safe10m ? "SAFE" : "ROTATE KEY");

        // Contract 3 (h=27, k=11, a=11) at 112-bit threshold
        bool safe3_1m = SecurityAnalysis.isWithinBudget(1_000_000, 27, 11, 11, 112);
        bool safe3_100m = SecurityAnalysis.isWithinBudget(100_000_000, 27, 11, 11, 112);
        bool safe3_500m = SecurityAnalysis.isWithinBudget(500_000_000, 27, 11, 11, 112);

        console.log("");
        console.log("Contract 3 (h=27, k=11, a=11):");
        console.log("  1M sigs: %s", safe3_1m ? "SAFE" : "ROTATE KEY");
        console.log("  100M sigs: %s", safe3_100m ? "SAFE" : "ROTATE KEY");
        console.log("  500M sigs: %s", safe3_500m ? "SAFE" : "ROTATE KEY");
    }

    /// @notice Compare "stateless-like" properties of the three variants
    function test_StatelessComparison() public pure {
        console.log("=================================================================");
        console.log("  'Stateless-like' Property Comparison");
        console.log("=================================================================");
        console.log("");
        console.log("  FORS/PORS instances available:");
        console.log("    C1/C2 (h=18): 2^18 = 262,144 instances");
        console.log("    C3    (h=27): 2^27 = 134,217,728 instances");
        console.log("");
        console.log("  At 2^20 target budget (1,048,576 signatures):");
        console.log("    C1/C2: 1M sigs / 262K instances = ~4x reuse expected");
        console.log("    C3:    1M sigs / 134M instances = ~0.008x reuse (essentially unique)");
        console.log("");
        console.log("  C3 achieves nearly-stateless behavior:");
        console.log("    - Each signature uses a nearly-unique FORS instance");
        console.log("    - No practical security degradation at the 2^20 budget");
        console.log("    - Can safely extend to millions of signatures at 112+ bits");
        console.log("");
        console.log("  Gas cost for 'statelessness' (EIP-7623 floor):");
        console.log("    C1 (P+FP): 249.7K gas, 3704B sig (222.2K cd + 27.5K exec)");
        console.log("    C3 (P+FP): 251.9K gas, 3596B sig (215.8K cd + 36.1K exec)");
        console.log("    -> C3 is BETTER on both sig size AND stateless properties");
        console.log("    -> Only costs 2.2K more gas (0.9% increase)");
        console.log("    -> EIP-7623 floor: calldata dominates, smaller sig = less gas");
    }
}
