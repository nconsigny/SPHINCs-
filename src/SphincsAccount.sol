// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ISigVerifier} from "./ISigVerifier.sol";

/// @title SphincsAccount - Hybrid ECDSA + SPHINCS+ account using a SHARED verifier
/// @notice The account stores pkSeed/pkRoot and passes them to a shared stateless verifier.
///         Uses ISigVerifier interface (ZKnox/Kohaku compatible).
///         The shared verifier is deployed once and used by all accounts.
///         Follows the ZKnox/Kohaku pattern (ISigVerifier with keys as arguments).
contract SphincsAccount is BaseAccount {
    using ECDSA for bytes32;

    IEntryPoint private immutable _entryPoint;
    address public immutable owner;          // ECDSA signer
    address public immutable verifier;       // Shared SphincsC6Shared address (same for all users)
    bytes32 public immutable pkSeed;         // SPHINCS+ public seed (per-user)
    bytes32 public immutable pkRoot;         // SPHINCS+ Merkle root (per-user)

    error NotOwnerOrEntryPoint();

    constructor(
        IEntryPoint ep,
        address _owner,
        address _verifier,
        bytes32 _pkSeed,
        bytes32 _pkRoot
    ) {
        _entryPoint = ep;
        owner = _owner;
        verifier = _verifier;
        pkSeed = _pkSeed;
        pkRoot = _pkRoot;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _requireForExecute() internal view override {
        require(
            msg.sender == address(entryPoint()) || msg.sender == owner,
            NotOwnerOrEntryPoint()
        );
    }

    /// @notice Validate hybrid signature: abi.encode(ecdsaSig, sphincsSig)
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        (bytes memory ecdsaSig, bytes memory sphincsSig) = abi.decode(
            userOp.signature,
            (bytes, bytes)
        );

        // 1. Verify ECDSA
        address recovered = userOpHash.recover(ecdsaSig);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        // 2. Verify SPHINCS+ via shared verifier (ISigVerifier interface)
        bytes memory key = abi.encodePacked(pkSeed, pkRoot);
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSelector(ISigVerifier.verify.selector, key, userOpHash, sphincsSig)
        );
        if (!success || result.length < 4) {
            return SIG_VALIDATION_FAILED;
        }
        bytes4 magicValue = abi.decode(result, (bytes4));
        if (magicValue != ISigVerifier.verify.selector) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    receive() external payable {}
}
