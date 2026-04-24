// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/interfaces/IEntryPoint.sol";
import "./SphincsAccount.sol";

/// @title SphincsAccountFactory - Factory using a SHARED verifier for all accounts
/// @notice Deploys only the account contract (not a per-user verifier).
///         The shared SphincsC6Shared verifier is deployed once and its address
///         is set in the factory constructor.
contract SphincsAccountFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable sharedVerifier;  // SphincsC6Shared — deployed once

    event AccountCreated(address indexed account, address indexed owner);

    constructor(IEntryPoint _entryPoint, address _sharedVerifier) {
        entryPoint = _entryPoint;
        sharedVerifier = _sharedVerifier;
    }

    /// @notice Create a new hybrid account with SPHINCS+ C6
    /// @param ecdsaOwner The ECDSA signer address
    /// @param pkSeed SPHINCS+ public seed
    /// @param pkRoot SPHINCS+ Merkle root
    function createAccount(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot
    ) external returns (SphincsAccount account) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot));

        account = new SphincsAccount{salt: salt}(
            entryPoint, ecdsaOwner, sharedVerifier, pkSeed, pkRoot
        );

        emit AccountCreated(address(account), ecdsaOwner);
    }

    function getAddress(
        address ecdsaOwner,
        bytes32 pkSeed,
        bytes32 pkRoot
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, pkSeed, pkRoot));
        bytes32 hash = keccak256(abi.encodePacked(
            type(SphincsAccount).creationCode,
            abi.encode(entryPoint, ecdsaOwner, sharedVerifier, pkSeed, pkRoot)
        ));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, hash
        )))));
    }
}
