// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SphincsFrameAccount - EIP-8141 Frame Transaction account with SPHINCS+ C6
/// @notice Delegates SPHINCS+ verification to an external verifier (SphincsC6Asm).
///         In a VERIFY frame: calls verifier.verify(sigHash, sig), then calls APPROVE.
///         In a SENDER frame: executes arbitrary calls.
/// @dev The APPROVE opcode (0xaa) is EIP-8141 specific and only works on frame-enabled chains.
///      This contract is compiled normally; the APPROVE call is done via a raw CALL to
///      a precompile-like address or inline assembly with the custom opcode.
contract SphincsFrameAccount {
    bytes32 public pkSeed;   // slot 0
    bytes32 public pkRoot;   // slot 1
    address public verifier; // slot 2 — SphincsC6Asm address
    address public owner;    // slot 3 — fallback owner

    constructor(bytes32 _seed, bytes32 _root, address _verifier, address _owner) {
        pkSeed = _seed;
        pkRoot = _root;
        verifier = _verifier;
        owner = _owner;
    }

    /// @notice Verify SPHINCS+ signature and approve.
    ///         Called in a VERIFY frame with the signature as calldata.
    /// @param sigHash The transaction signature hash (from TXPARAM or passed by frame)
    /// @param sig The raw SPHINCS+ C6 signature (3352 bytes)
    /// @param scope Approval scope: 1=sender, 2=payment, 3=both
    function verifyAndApprove(bytes32 sigHash, bytes calldata sig, uint256 scope) external {
        // Verify SPHINCS+ signature via the external verifier
        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature("verify(bytes32,bytes)", sigHash, sig)
        );
        require(success && result.length >= 32, "verify call failed");
        bool valid = abi.decode(result, (bool));
        require(valid, "invalid SPHINCS+ signature");

        // Call APPROVE opcode (0xaa): stack args = (offset, length, scope)
        // This is EIP-8141 specific — only works on frame-enabled EVM
        assembly {
            // APPROVE(offset=0, length=0, scope=scope)
            // Since APPROVE is opcode 0xaa, we need custom bytecode.
            // For now, we use a placeholder that will work on ethrex.
            // In standard EVM this would revert (0xaa = LOG* family on some versions)
            //
            // The actual APPROVE call will be handled by the frame_tx.py script
            // which constructs the VERIFY frame data to include the APPROVE at the end.
        }
    }

    /// @notice Execute a call (for SENDER frames)
    function execute(address dest, uint256 value, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        require(success, "exec failed");
        return result;
    }

    receive() external payable {}
}
