// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./JardinAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// @title JardinAccountFactory — Deterministic CREATE2 factory for JARDÍN
///        accounts (ECDSA + SPX primary + FORS+C compact; C11 is attached
///        post-deploy as optional recovery).
contract JardinAccountFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable spxVerifier;
    address public immutable forscVerifier;

    event AccountCreated(address indexed account, address indexed owner, bytes32 spxPkSeed, bytes32 spxPkRoot);

    constructor(IEntryPoint _entryPoint, address _spxVerifier, address _forscVerifier) {
        entryPoint = _entryPoint;
        spxVerifier = _spxVerifier;
        forscVerifier = _forscVerifier;
    }

    /// @notice Deploy a new hybrid ECDSA + SPX account (deterministic via CREATE2)
    function createAccount(address ecdsaOwner, bytes32 spxPkSeed, bytes32 spxPkRoot)
        external
        returns (JardinAccount)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, spxPkSeed, spxPkRoot));
        JardinAccount account = new JardinAccount{salt: salt}(
            entryPoint, ecdsaOwner, spxVerifier, forscVerifier, spxPkSeed, spxPkRoot
        );
        emit AccountCreated(address(account), ecdsaOwner, spxPkSeed, spxPkRoot);
        return account;
    }

    /// @notice Pre-compute account address before deployment
    function getAddress(address ecdsaOwner, bytes32 spxPkSeed, bytes32 spxPkRoot)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, spxPkSeed, spxPkRoot));
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        type(JardinAccount).creationCode,
                        abi.encode(entryPoint, ecdsaOwner, spxVerifier, forscVerifier, spxPkSeed, spxPkRoot)
                    )
                )
            )
        );
        return address(uint160(uint256(hash)));
    }
}
