// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./JardinAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// @title JardinAccountFactory — Deterministic CREATE2 factory for JARDÍN accounts
contract JardinAccountFactory {
    IEntryPoint public immutable entryPoint;
    address public immutable c11Verifier;
    address public immutable forscVerifier;

    event AccountCreated(address indexed account, address indexed owner, bytes32 masterPkSeed, bytes32 masterPkRoot);

    constructor(IEntryPoint _entryPoint, address _c11Verifier, address _forscVerifier) {
        entryPoint = _entryPoint;
        c11Verifier = _c11Verifier;
        forscVerifier = _forscVerifier;
    }

    /// @notice Deploy a new hybrid ECDSA + JARDÍN account (deterministic via CREATE2)
    function createAccount(address ecdsaOwner, bytes32 masterPkSeed, bytes32 masterPkRoot)
        external
        returns (JardinAccount)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, masterPkSeed, masterPkRoot));
        JardinAccount account = new JardinAccount{salt: salt}(
            entryPoint, ecdsaOwner, c11Verifier, forscVerifier, masterPkSeed, masterPkRoot
        );
        emit AccountCreated(address(account), ecdsaOwner, masterPkSeed, masterPkRoot);
        return account;
    }

    /// @notice Pre-compute account address before deployment
    function getAddress(address ecdsaOwner, bytes32 masterPkSeed, bytes32 masterPkRoot)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(ecdsaOwner, masterPkSeed, masterPkRoot));
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        type(JardinAccount).creationCode,
                        abi.encode(entryPoint, ecdsaOwner, c11Verifier, forscVerifier, masterPkSeed, masterPkRoot)
                    )
                )
            )
        );
        return address(uint160(uint256(hash)));
    }
}
