// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Create2.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./SphincsAccount.sol";
import "./SPHINCs-C2Asm.sol";
import "./SPHINCs-C6Asm.sol";

/// @title SphincsAccountFactory - Factory for hybrid ECDSA + SPHINCS+ 4337 accounts
/// @notice Deploys a per-user SPHINCS+ verifier and a SphincsAccount in a single call.
///         Supports variant 2 (FORS+C h=18) and variant 6 (FORS+C h=24).
contract SphincsAccountFactory {
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed verifier, address indexed owner, uint8 variant);

    error InvalidVariant(uint8 variant);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @param variant     2 = FORS+C h=18, 6 = FORS+C h=24 (gas-optimal)
    function createAccount(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot,
        uint8 variant
    ) external returns (SphincsAccount account) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot, variant));

        address verifierAddr;
        if (variant == 2) {
            verifierAddr = address(new SphincsC2Asm{salt: salt}(pkSeed, pkRoot));
        } else if (variant == 6) {
            verifierAddr = address(new SphincsC6Asm{salt: salt}(pkSeed, pkRoot));
        } else {
            revert InvalidVariant(variant);
        }

        account = new SphincsAccount{salt: salt}(entryPoint, ecdsaOwner, verifierAddr);
        emit AccountCreated(address(account), verifierAddr, ecdsaOwner, variant);
    }

    function getAddress(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot,
        uint8 variant
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot, variant));

        bytes32 verifierHash;
        if (variant == 2) {
            verifierHash = keccak256(abi.encodePacked(
                type(SphincsC2Asm).creationCode,
                abi.encode(pkSeed, pkRoot)
            ));
        } else if (variant == 6) {
            verifierHash = keccak256(abi.encodePacked(
                type(SphincsC6Asm).creationCode,
                abi.encode(pkSeed, pkRoot)
            ));
        } else {
            revert InvalidVariant(variant);
        }
        address verifierAddr = Create2.computeAddress(salt, verifierHash);

        bytes32 accountHash = keccak256(abi.encodePacked(
            type(SphincsAccount).creationCode,
            abi.encode(entryPoint, ecdsaOwner, verifierAddr)
        ));
        return Create2.computeAddress(salt, accountHash);
    }
}
