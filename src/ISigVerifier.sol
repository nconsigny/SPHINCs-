// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

/**
 * @dev Signature verifier interface (ZKnox/Kohaku standard).
 * @notice Compatible with Falcon, Dilithium, SPHINCS+, and any PQ scheme.
 *         See https://github.com/ZKNoxHQ/InterfaceVerifier
 */
interface ISigVerifier {
    function setKey(bytes calldata key) external returns (bytes memory);

    /**
     * @dev Verifies `signature` as a valid signature of `hash` by `key`.
     *
     * MUST return ISigVerifier.verify.selector if the signature is valid.
     * SHOULD return 0xffffffff or revert if the signature is not valid.
     */
    function verify(bytes calldata key, bytes32 hash, bytes calldata signature) external returns (bytes4);
}
