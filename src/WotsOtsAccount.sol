// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// @title WotsOtsAccount — Post-quantum one-time signature ERC-4337 account
/// @notice WOTS+C (checksum-less WOTS with grinding) verification inlined in assembly.
///         Single-use: the key is marked spent after the first valid signature.
///         Parameters: w=16, n=128 bits, l=32 chains, targetSum=240, z=0.
///         Signature: 516 bytes (32×16 chain values + 4 byte grinding nonce).
///
/// @dev Storage layout (raw slots, no Solidity state variables):
///        slot 0: pkSeed   (bytes32, top 128 bits meaningful)
///        slot 1: pkHash   (bytes32, top 128 bits = compressed WOTS PK, bit 0 = used flag)
///
///      The used flag is packed into bit 0 of pkHash. Since n=128 and values are
///      left-aligned, the lower 128 bits are always zero. Marking used flips bit 0,
///      costing only 2900 gas (warm nonzero→nonzero SSTORE) instead of 20000 gas
///      for a separate 0→1 storage slot.
///
///      Memory layout (fixed, no allocator):
///        0x00: seed         (written once from slot 0, warm for all keccak calls)
///        0x20: ADRS         (modified in-place per hash)
///        0x40: input/value  (chain value or left child)
///        0x60: input2       (count for digest, or right child)
///        0x80..0x47F: 32 endpoint buffer (32×32 bytes)
///
///      Standalone ADRS (no SPHINCS+ layer/tree/keyPair):
///        chain hash: (chainIndex << 64) | (position << 32)
///        PK compress: (1 << 128)  [WOTS_PK type]
///        digest: 0
contract WotsOtsAccount is BaseAccount {

    IEntryPoint private immutable _entryPoint;

    constructor(IEntryPoint ep, bytes32 _pkSeed, bytes32 _pkHash) {
        _entryPoint = ep;
        assembly {
            sstore(0, _pkSeed)
            sstore(1, _pkHash)
        }
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Only entryPoint can call execute (one-time wallet, no persistent owner)
    function _requireForExecute() internal view override {
        require(msg.sender == address(entryPoint()));
    }

    /// @notice Check if this one-time key has been used
    function isUsed() external view returns (bool used) {
        assembly {
            used := and(sload(1), 1)
        }
    }

    /// @notice Read pkSeed
    function pkSeed() external view returns (bytes32 s) {
        assembly { s := sload(0) }
    }

    /// @notice Read pkHash (with used flag in bit 0)
    function pkHash() external view returns (bytes32 h) {
        assembly { h := sload(1) }
    }

    /// @notice Validate WOTS+C one-time signature — full inline assembly
    /// @dev Signature format: 32 chain values (16 bytes each) || count (4 bytes) = 516 bytes
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        validationData = _verifyWotsOts(userOp.signature, userOpHash);
    }

    /// @dev Full WOTS+C verification in assembly.
    ///      Returns 0 on success and 1 on failure without exiting validateUserOp early,
    ///      so BaseAccount can still run nonce checks and prefund payment.
    function _verifyWotsOts(bytes calldata sig, bytes32 userOpHash) private returns (uint256 validationData) {
        assembly {
            // ==============================================================
            // CONSTANTS
            // ==============================================================
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
            let result := 1
            let freeMemPtr := mload(0x40)

            // ==============================================================
            // STEP 0: Load state, check used flag
            // ==============================================================
            let seed := sload(0)
            let pkHashRaw := sload(1)

            // Check used flag (bit 0)
            if iszero(and(pkHashRaw, 1)) {
                let pkHashClean := and(pkHashRaw, N_MASK)

                // Write seed to 0x00 — warm for all subsequent keccak calls
                mstore(0x00, seed)

                // ==========================================================
                // STEP 1: Validate signature length = 516
                // ==========================================================
                if eq(sig.length, 516) {
                    let sigOff := sig.offset

                    // ======================================================
                    // STEP 2: Read count, compute digest
                    // ======================================================
                    let count := shr(224, calldataload(add(sigOff, 512)))

                    mstore(0x20, 0)                      // ADRS = 0
                    mstore(0x40, userOpHash)             // message
                    mstore(0x60, count)                  // count
                    let d := keccak256(0x00, 0x80)

                    // ======================================================
                    // STEP 3: Extract 32 base-16 digits, validate sum = 240
                    // ======================================================
                    let digitSum := 0
                    for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                        digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
                    }
                    if eq(digitSum, 240) {
                        // ==================================================
                        // STEP 4: Complete 32 chains, store endpoints
                        // ==================================================
                        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                            let digit := and(shr(mul(i, 4), d), 0xF)
                            let steps := sub(15, digit)
                            let val := and(calldataload(add(sigOff, mul(i, 16))), N_MASK)
                            let chainAdrs := shl(64, i)

                            for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                                let pos := add(digit, step)
                                mstore(0x20, or(chainAdrs, shl(32, pos)))
                                mstore(0x40, val)
                                val := and(keccak256(0x00, 0x60), N_MASK)
                            }

                            mstore(add(0x80, mul(i, 0x20)), val)
                        }

                        // ==================================================
                        // STEP 5: PK compression
                        // ==================================================
                        mstore(0x20, shl(128, 1))
                        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                            mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
                        }
                        let computedPk := and(keccak256(0x00, 0x440), N_MASK)

                        // ==================================================
                        // STEP 6: Compare and set used flag
                        // ==================================================
                        if eq(computedPk, pkHashClean) {
                            sstore(1, or(pkHashRaw, 1))
                            result := 0
                        }
                    }
                }
            }
            // Write the result into Solidity's return slot instead of using
            // assembly `return`, which would exit validateUserOp early.
            mstore(0x40, freeMemPtr)
            mstore(0x60, 0)
            validationData := result
        }
    }

    receive() external payable {}
}
