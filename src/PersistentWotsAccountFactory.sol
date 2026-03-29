// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Create2.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./PersistentWotsAccount.sol";

/// @title PersistentWotsAccountFactory
/// @notice CREATE2 factory for the persistent h=9 WOTS+C account.
contract PersistentWotsAccountFactory {
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, bytes32 indexed pkSeed, bytes32 indexed pkRoot);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function createAccount(
        bytes32 pkSeed,
        bytes32 pkRoot
    ) external returns (PersistentWotsAccount account) {
        bytes32 salt = keccak256(abi.encodePacked(pkSeed, pkRoot));
        account = new PersistentWotsAccount{salt: salt}(entryPoint, pkSeed, pkRoot);
        emit AccountCreated(address(account), pkSeed, pkRoot);
    }

    function getAddress(
        bytes32 pkSeed,
        bytes32 pkRoot
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(pkSeed, pkRoot));
        bytes32 hash = keccak256(
            abi.encodePacked(type(PersistentWotsAccount).creationCode, abi.encode(entryPoint, pkSeed, pkRoot))
        );
        return Create2.computeAddress(salt, hash);
    }
}
