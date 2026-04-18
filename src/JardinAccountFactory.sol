// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./JardinAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// @title JardinAccountFactory — Deterministic CREATE2 factory for JARDINERO
///        accounts (ECDSA + T0 primary + FORS+C compact; C11 is attached
///        post-deploy as optional recovery).
contract JardinAccountFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable t0Verifier;
    address public immutable forscVerifier;

    event AccountCreated(address indexed account, address indexed owner, bytes32 t0PkSeed, bytes32 t0PkRoot);

    constructor(IEntryPoint _entryPoint, address _t0Verifier, address _forscVerifier) {
        entryPoint = _entryPoint;
        t0Verifier = _t0Verifier;
        forscVerifier = _forscVerifier;
    }

    /// @notice Deploy a new hybrid ECDSA + T0 account (deterministic via CREATE2)
    function createAccount(address ecdsaOwner, bytes32 t0PkSeed, bytes32 t0PkRoot)
        external
        returns (JardinAccount)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, t0PkSeed, t0PkRoot));
        JardinAccount account = new JardinAccount{salt: salt}(
            entryPoint, ecdsaOwner, t0Verifier, forscVerifier, t0PkSeed, t0PkRoot
        );
        emit AccountCreated(address(account), ecdsaOwner, t0PkSeed, t0PkRoot);
        return account;
    }

    /// @notice Pre-compute account address before deployment
    function getAddress(address ecdsaOwner, bytes32 t0PkSeed, bytes32 t0PkRoot)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, t0PkSeed, t0PkRoot));
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        type(JardinAccount).creationCode,
                        abi.encode(entryPoint, ecdsaOwner, t0Verifier, forscVerifier, t0PkSeed, t0PkRoot)
                    )
                )
            )
        );
        return address(uint160(uint256(hash)));
    }
}
