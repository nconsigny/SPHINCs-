// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SphincsAccount - Hybrid ECDSA + SPHINCS+ ERC-4337 Smart Account
/// @notice Post-quantum secure account requiring both ECDSA and SPHINCS+ signatures.
///         The SPHINCS+ verifier is a separate contract storing the user's pkSeed/pkRoot.
contract SphincsAccount is BaseAccount {
    using ECDSA for bytes32;

    IEntryPoint private immutable _entryPoint;
    address public immutable owner;       // ECDSA signer (EOA address)
    address public immutable verifier;    // SphincsWc*Asm contract instance

    error NotOwnerOrEntryPoint();

    constructor(IEntryPoint ep, address _owner, address _verifier) {
        _entryPoint = ep;
        owner = _owner;
        verifier = _verifier;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Only entryPoint or owner can call execute
    function _requireForExecute() internal view override {
        require(
            msg.sender == address(entryPoint()) || msg.sender == owner,
            NotOwnerOrEntryPoint()
        );
    }

    /// @notice Validate hybrid signature: abi.encode(ecdsaSig, sphincsSig)
    /// @dev ecdsaSig = 65 bytes (r,s,v), sphincsSig = variable length SPHINCS+ sig
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        // Decode hybrid signature
        (bytes memory ecdsaSig, bytes memory sphincsSig) = abi.decode(
            userOp.signature,
            (bytes, bytes)
        );

        // 1. Verify ECDSA signature
        address recovered = userOpHash.recover(ecdsaSig);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        // 2. Verify SPHINCS+ signature via verifier contract
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes32,bytes)", userOpHash, sphincsSig)
        );
        if (!success || result.length < 32) {
            return SIG_VALIDATION_FAILED;
        }
        bool valid = abi.decode(result, (bool));
        if (!valid) {
            return SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    receive() external payable {}
}
