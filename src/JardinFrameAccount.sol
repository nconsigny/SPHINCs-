// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinFrameAccount — EIP-8141 Frame Transaction account with JARDÍN (pure PQ)
/// @notice Two signature types, no ECDSA — post-quantum only:
///   Type 1 (0x01): Stateless SPHINCs- C11 + optional sub-key registration
///   Type 2 (0x02): FORS+C compact via registered sub-key slot
///
/// Keys are in storage (rotatable). The on-chain identity is the contract address.
/// Frame tx protocol provides replay protection via its own nonce mechanism.
contract JardinFrameAccount {

    address public c11Verifier;    // slot 0 — Shared C11 verifier
    address public forscVerifier;  // slot 1 — JARDÍN FORS+C verifier
    bytes32 public masterPkSeed;   // slot 2
    bytes32 public masterPkRoot;   // slot 3
    address public owner;          // slot 4 — admin (for key rotation)

    /// @notice Sub-key slots: keccak256(r) => keccak256(subPkSeed, subPkRoot)
    mapping(bytes32 => bytes32) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotSelf();

    constructor(
        address _c11Verifier,
        address _forscVerifier,
        bytes32 _masterPkSeed,
        bytes32 _masterPkRoot,
        address _owner
    ) {
        c11Verifier = _c11Verifier;
        forscVerifier = _forscVerifier;
        masterPkSeed = _masterPkSeed;
        masterPkRoot = _masterPkRoot;
        owner = _owner;
    }

    /// @notice Rotate master SPHINCs- keys (via self-call through execute)
    function rotateMasterKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotSelf());
        masterPkSeed = newPkSeed;
        masterPkRoot = newPkRoot;
    }

    /// @notice Rotate verifier addresses (upgrade path)
    function rotateVerifiers(address newC11, address newForsc) external {
        require(msg.sender == address(this), NotSelf());
        c11Verifier = newC11;
        forscVerifier = newForsc;
    }

    /// @notice Rotate owner
    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotSelf());
        require(newOwner != address(0));
        owner = newOwner;
    }

    /// @notice Verify JARDÍN signature and approve the frame transaction.
    ///         Called in a VERIFY frame. Signature layout:
    ///         Type 1: [0x01][r 32B][subPkSeed 16B][subPkRoot 16B][C11 sig ~3976B]
    ///         Type 2: [0x02][H(r) 32B][subPkSeed 16B][subPkRoot 16B][FORS+C sig]
    /// @param sigHash The transaction hash (from TXPARAM)
    /// @param sig The JARDÍN signature (Type 1 or Type 2)
    /// @param scope Approval scope: 1=sender, 2=payment, 3=both
    function verifyAndApprove(bytes32 sigHash, bytes calldata sig, uint256 scope) external {
        require(sig.length > 65, InvalidSignatureType());

        uint8 sigType = uint8(sig[0]);

        if (sigType == 0x01) {
            // ── Type 1: C11 stateless + optional sub-key registration ──
            bytes32 r       = bytes32(sig[1:33]);
            bytes16 subSeed = bytes16(sig[33:49]);
            bytes16 subRoot = bytes16(sig[49:65]);
            bytes calldata c11Sig = sig[65:];

            (bool ok, bytes memory res) = c11Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    masterPkSeed, masterPkRoot, sigHash, c11Sig
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "C11 verify failed");

            if (r != bytes32(0)) {
                bytes32 key = keccak256(abi.encodePacked(r));
                require(slots[key] == bytes32(0), SlotAlreadyRegistered());
                slots[key] = keccak256(abi.encodePacked(subSeed, subRoot));
            }

        } else if (sigType == 0x02) {
            // ── Type 2: FORS+C compact ──
            bytes32 key     = bytes32(sig[1:33]);
            bytes16 subSeed = bytes16(sig[33:49]);
            bytes16 subRoot = bytes16(sig[49:65]);
            bytes calldata forscSig = sig[65:];

            require(
                keccak256(abi.encodePacked(subSeed, subRoot)) == slots[key],
                UnregisteredSlot()
            );

            (bool ok, bytes memory res) = forscVerifier.staticcall(
                abi.encodeWithSignature(
                    "verifyForsCUnbalanced(bytes32,bytes32,bytes32,bytes)",
                    bytes32(subSeed), bytes32(subRoot), sigHash, forscSig
                )
            );
            require(ok && res.length >= 32 && abi.decode(res, (bool)), "FORS+C verify failed");

        } else {
            revert InvalidSignatureType();
        }

        // APPROVE frame transaction (EIP-8141 opcode 0xAA)
        // scope: 1=sender, 2=payment, 3=both
        assembly {
            // APPROVE is implemented as opcode 0xAA on frame-enabled chains (ethrex)
            // Stack: scope → APPROVE
            // This is a no-op on standard EVM; frame_tx.py handles the raw bytecode
        }
    }

    /// @notice Execute a call (for SENDER frames)
    function execute(address dest, uint256 value, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == address(this) || msg.sender == owner, NotSelf());
        (bool success, bytes memory result) = dest.call{value: value}(data);
        require(success, "exec failed");
        return result;
    }

    receive() external payable {}
}
