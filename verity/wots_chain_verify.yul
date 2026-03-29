/// @title wots_chain_verify — Linked Yul library for WOTS+C chain verification
/// @notice Linked into the Verity-compiled WotsOtsVerifier contract.
///         Performs digest computation, digit extraction + sum check,
///         32 chain completions, and PK compression.
/// @dev Compile with: lake exe verity-compiler --link verity/wots_chain_verify.yul
///
/// Parameters: w=16, n=128 bits, l=32, targetSum=240, z=0, sig=516 bytes
///
/// Memory layout (matches WotsOtsAccount.sol assembly):
///   0x00: seed          (written by caller, warm)
///   0x20: ADRS          (modified in-place per hash)
///   0x40: input/value   (chain value)
///   0x60: count/input2  (digest input)
///   0x80..0x47F: 32 endpoint buffer (32 x 32 bytes)

/// @param sigOffset  Calldata offset where sig bytes start
/// @param sigLen     Length of sig bytes (must be 516)
/// @param message    The message hash (bytes32)
/// @param seed       The pkSeed value
/// @return computedPk  Reconstructed PK (top 128 bits), or 0 on failure
function wotsChainVerify(sigOffset, sigLen, message, seed) -> computedPk {
    computedPk := 0
    let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

    // Validate signature length = 516
    if iszero(eq(sigLen, 516)) { leave }

    // Write seed to memory 0x00 (warm for all subsequent keccak calls)
    mstore(0x00, seed)

    // Read count from sig[512..515] (4 bytes, big-endian)
    let count := shr(224, calldataload(add(sigOffset, 512)))

    // Compute digest = keccak256(seed || 0 || message || count)
    mstore(0x20, 0)
    mstore(0x40, message)
    mstore(0x60, count)
    let d := keccak256(0x00, 0x80)

    // Extract 32 base-16 digits, validate sum = 240
    let digitSum := 0
    for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
        digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
    }
    if iszero(eq(digitSum, 240)) { leave }

    // Complete 32 chains
    for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
        let digit := and(shr(mul(i, 4), d), 0xF)
        let steps := sub(15, digit)

        // Read sigma[i] from calldata
        let val := and(calldataload(add(sigOffset, mul(i, 16))), N_MASK)

        // Chain ADRS base: chainIndex << 64
        let chainAdrs := shl(64, i)

        // Chain hash inner loop
        for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
            let pos := add(digit, step)
            mstore(0x20, or(chainAdrs, shl(32, pos)))
            mstore(0x40, val)
            val := and(keccak256(0x00, 0x60), N_MASK)
        }

        // Store endpoint
        mstore(add(0x80, mul(i, 0x20)), val)
    }

    // PK compression: keccak256(seed || pkAdrs || 32 endpoints)
    mstore(0x20, shl(128, 1))
    for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
        mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
    }
    computedPk := and(keccak256(0x00, 0x440), N_MASK)
}
