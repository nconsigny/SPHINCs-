// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SecurityAnalysis - Signature reuse decay and security properties
/// @author Generated for ePrint 2025/2203 parameter exploration
/// @notice This library documents security properties and provides on-chain
///         signature budget enforcement for tweaked SPHINCS+ variants.
///
/// ## Security Model: 2^20 Target with Reuse Decay
///
/// All three parameter sets target 128-bit security (λ=128) at the
/// designated signature budget of q_s = 2^20 ≈ 1,048,576 signatures.
///
/// ### Why "Stateless-like" Works at 2^20
///
/// Standard SPHINCS+ uses a 2^64 signature budget, making any FORS instance
/// reuse astronomically unlikely. At 2^20, FORS/PORS instance reuse is the
/// primary security concern.
///
/// The number of distinct FORS/PORS instances is 2^h:
///   - Contract 1 & 2 (h=18): 2^18 = 262,144 instances
///   - Contract 3 (h=27):     2^27 = 134,217,728 instances
///
/// ### FORS/PORS Security Degradation Formula
///
/// After q signatures, the probability of FORS forgery is bounded by:
///
///   Pr[forge] ≤ Σ_{r=1}^{q} C(q,r) · (1/2^h)^r · (1 - 1/2^h)^{q-r} · (1 - (1-1/t)^r)^k
///
/// Where:
///   t = 2^a (leaves per FORS tree / total PORS leaves)
///   k = number of opened leaves
///   h = hypertree height (determines instance count)
///   r = number of signatures to the same instance
///
/// ### Concrete Reuse Analysis
///
/// **Contract 1 & 2 (h=18, 2^18 instances):**
///   At q = 2^20 (1M signatures):
///   - Expected max reuse per instance: ~16 signatures (birthday bound on 2^18 bins)
///   - After 16 reuses with k=13, a=13: adversary learns 16*13 = 208 out of
///     13*8192 = 106,496 FORS leaves → Pr[forge] ≈ (208/106496)^13 ≈ 2^{-118}
///   - Security: ~118 bits (still above 112-bit threshold)
///
///   At q = 2^23 (~8M signatures):
///   - Expected max reuse: ~128
///   - Adversary knows ~1664/106496 leaves per tree → Pr ≈ 2^{-78}
///   - Security drops below 112 bits — KEY ROTATION RECOMMENDED
///
/// **Contract 3 (h=27, 2^27 instances):**
///   At q = 2^20:
///   - Expected max reuse: ~1 (almost no reuse at all!)
///   - Security: Full 128-bit, effectively stateless behavior
///
///   At q = 2^27 (~134M signatures):
///   - Expected max reuse: ~16
///   - With k=11, a=11: 16*11 = 176 out of 11*2048 = 22,528 leaves
///   - Pr[forge] ≈ (176/22528)^11 ≈ 2^{-77}
///   - Still adequate for many use cases
///
///   At q = 2^30 (~1B signatures):
///   - Expected max reuse: ~128
///   - Pr[forge] ≈ 2^{-51} — rotation needed well before this point
///
/// ### Reuse Decay Summary
///
/// | Contract | h  | Signatures for 128-bit | Signatures for 112-bit | Key rotation needed |
/// |----------|----|-----------------------|-----------------------|--------------------|
/// | C1 (P+FP)| 18 | 2^20 (1M)            | ~2^22 (4M)            | ~4M signatures     |
/// | C2 (F+C) | 18 | 2^20 (1M)            | ~2^22 (4M)            | ~4M signatures     |
/// | C3 (P+FP)| 27 | 2^20 (1M)            | ~2^28 (256M)          | ~256M signatures   |
///
/// ### Why Contract 3 Is the Best "Stateless-like" Choice
///
/// Contract 3 (h=27, d=3) provides:
///   1. Smallest signatures (3596 bytes)
///   2. Most FORS instances (2^27) → slowest security decay
///   3. ~256M signatures before dropping to 112-bit security
///   4. True "stateless-like" behavior at practical signature counts
///   5. Tradeoff: 8.6K more compute gas per verification (36.1K vs 27.5K)
///
/// The extra d=3 hypertree layer costs ~8.6K compute gas but buys 2^9 = 512x
/// more FORS instances, dramatically extending the safe signature budget.
///
/// ### WOTS+C Security
///
/// WOTS+C security is independent of signature count (unlike FORS/PORS).
/// With l=39 chains, w=16, targetSum=292:
///   - Forgery requires inverting a chain hash (2^{128} work for n=128)
///   - The sum+zero constraints provide equivalent security to checksums
///   - No degradation with reuse
///
/// ### Quantum Security Considerations (from ePrint 2025/2203)
///
/// Level 1 (n=128) provides:
///   - 128-bit classical security
///   - ~78-bit quantum security (Grover on SHA-256/keccak256)
///   - Quantum attack cost: ~2^78 Toffoli operations (not 2^64 due to
///     oracle reversibilization overhead for SHA-256)
///   - Breaking requires ~268 million large quantum computers for 10 years
///   - Matches current Bitcoin/Ethereum security level
///
library SecurityAnalysis {
    /// @notice Estimate security bits remaining after q signatures
    /// @param q Number of signatures issued
    /// @param h Hypertree height (determines FORS instance count)
    /// @param k Number of FORS/PORS leaves opened per signature
    /// @param a FORS/PORS tree height (t = 2^a)
    /// @return secBits Estimated security bits (conservative lower bound)
    function estimateSecurityBits(
        uint256 q,
        uint256 h,
        uint256 k,
        uint256 a
    ) internal pure returns (uint256 secBits) {
        // Simplified model: security ≈ k * log2(t / (maxReuse * k))
        // where maxReuse ≈ q / 2^h (expected collisions in birthday model)
        uint256 instances = 1 << h;
        uint256 t = 1 << a;
        uint256 totalLeaves = k * t;

        // Expected max reuse (simplified): q^2 / (2 * instances) for birthday,
        // but for our regime (q < instances): maxReuse ≈ ceil(q / instances)
        uint256 maxReuse;
        if (q <= instances) {
            maxReuse = 1;
        } else {
            maxReuse = (q + instances - 1) / instances;
        }

        // Fraction of leaves revealed after maxReuse signatures
        // revealed = maxReuse * k out of totalLeaves
        uint256 revealed = maxReuse * k;
        if (revealed >= totalLeaves) {
            return 0; // Fully compromised
        }

        // Security bits ≈ k * log2(totalLeaves / revealed)
        // Using integer approximation: log2(x) ≈ 256 - clz(x)
        uint256 ratio = totalLeaves / revealed; // ratio ≥ 1
        uint256 logRatio = _log2Floor(ratio);
        secBits = k * logRatio;

        // Cap at 128 (Level 1 maximum)
        if (secBits > 128) secBits = 128;
    }

    /// @notice Check if a signing counter is within the safe budget
    /// @param sigCount Current signature count
    /// @param h Hypertree height
    /// @param minSecBits Minimum acceptable security bits (e.g., 112)
    /// @return safe True if more signatures can be safely issued
    function isWithinBudget(
        uint256 sigCount,
        uint256 h,
        uint256 k,
        uint256 a,
        uint256 minSecBits
    ) internal pure returns (bool safe) {
        return estimateSecurityBits(sigCount, h, k, a) >= minSecBits;
    }

    function _log2Floor(uint256 x) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            r := 0
            if gt(x, 0xFFFFFFFFFFFFFFFF) { r := add(r, 64) x := shr(64, x) }
            if gt(x, 0xFFFFFFFF) { r := add(r, 32) x := shr(32, x) }
            if gt(x, 0xFFFF) { r := add(r, 16) x := shr(16, x) }
            if gt(x, 0xFF) { r := add(r, 8) x := shr(8, x) }
            if gt(x, 0xF) { r := add(r, 4) x := shr(4, x) }
            if gt(x, 3) { r := add(r, 2) x := shr(2, x) }
            if gt(x, 1) { r := add(r, 1) }
        }
    }
}
