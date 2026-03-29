// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Create2.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./WotsOtsAccount.sol";

/// @title WotsOtsAccountFactory — Factory for WOTS+C one-time signature accounts
/// @notice Deploys a WotsOtsAccount per user via CREATE2 in a single call.
contract WotsOtsAccountFactory {
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, bytes32 indexed pkSeed);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @notice Deploy a new WOTS+C one-time account
    /// @param pkSeed  WOTS+C public seed (top 128 bits)
    /// @param pkHash  Compressed WOTS+C public key (top 128 bits, bit 0 must be 0)
    /// @return account The deployed WotsOtsAccount
    function createAccount(
        bytes32 pkSeed,
        bytes32 pkHash
    ) external returns (WotsOtsAccount account) {
        bytes32 salt = keccak256(abi.encodePacked(pkSeed, pkHash));
        account = new WotsOtsAccount{salt: salt}(entryPoint, pkSeed, pkHash);
        emit AccountCreated(address(account), pkSeed);
    }

    /// @notice Precompute the account address for given parameters
    function getAddress(
        bytes32 pkSeed,
        bytes32 pkHash
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(pkSeed, pkHash));
        bytes32 hash = keccak256(abi.encodePacked(
            type(WotsOtsAccount).creationCode,
            abi.encode(entryPoint, pkSeed, pkHash)
        ));
        return Create2.computeAddress(salt, hash);
    }
}
