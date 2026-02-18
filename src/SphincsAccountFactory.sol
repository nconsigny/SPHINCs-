// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Create2.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./SphincsAccount.sol";
import "./SphincsWcFc18Asm.sol";
import "./SphincsWcPfp27Asm.sol";

/// @title SphincsAccountFactory - Factory for hybrid ECDSA + SPHINCS+ 4337 accounts
/// @notice Deploys a per-user SPHINCS+ verifier and a SphincsAccount in a single call.
///         Supports variant 2 (FORS+C h=18) and variant 3 (PORS+FP h=27).
contract SphincsAccountFactory {
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed verifier, address indexed owner, uint8 variant);

    error InvalidVariant(uint8 variant);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @notice Create a new hybrid ECDSA + SPHINCS+ account
    /// @param ecdsaOwner  The ECDSA signer address (EOA)
    /// @param pkSeed      SPHINCS+ public seed
    /// @param pkRoot      SPHINCS+ public root
    /// @param variant     2 = FORS+C h=18 (lowest gas), 3 = PORS+FP h=27 (strongest security)
    /// @return account    The deployed SphincsAccount
    function createAccount(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot,
        uint8 variant
    ) external returns (SphincsAccount account) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot, variant));

        // Deploy verifier
        address verifierAddr;
        if (variant == 2) {
            verifierAddr = address(new SphincsWcFc18Asm{salt: salt}(pkSeed, pkRoot));
        } else if (variant == 3) {
            verifierAddr = address(new SphincsWcPfp27Asm{salt: salt}(pkSeed, pkRoot));
        } else {
            revert InvalidVariant(variant);
        }

        // Deploy account
        account = new SphincsAccount{salt: salt}(entryPoint, ecdsaOwner, verifierAddr);

        emit AccountCreated(address(account), verifierAddr, ecdsaOwner, variant);
    }

    /// @notice Precompute the account address for given parameters
    function getAddress(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot,
        uint8 variant
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot, variant));

        // Compute verifier address first
        bytes32 verifierHash;
        if (variant == 2) {
            verifierHash = keccak256(abi.encodePacked(
                type(SphincsWcFc18Asm).creationCode,
                abi.encode(pkSeed, pkRoot)
            ));
        } else if (variant == 3) {
            verifierHash = keccak256(abi.encodePacked(
                type(SphincsWcPfp27Asm).creationCode,
                abi.encode(pkSeed, pkRoot)
            ));
        } else {
            revert InvalidVariant(variant);
        }
        address verifierAddr = Create2.computeAddress(salt, verifierHash);

        // Compute account address
        bytes32 accountHash = keccak256(abi.encodePacked(
            type(SphincsAccount).creationCode,
            abi.encode(entryPoint, ecdsaOwner, verifierAddr)
        ));
        return Create2.computeAddress(salt, accountHash);
    }
}
