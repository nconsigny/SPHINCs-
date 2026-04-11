// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title JardinAccount — Hybrid ECDSA + JARDÍN ERC-4337 account
/// @notice Every UserOp requires ECDSA + post-quantum signature (belt-and-suspenders).
///   Type 1 (0x01): ECDSA + C11 stateless + optional sub-key registration
///   Type 2 (0x02): ECDSA + FORS+C compact via registered sub-key slot
///
/// No on-chain leaf counter. The leaf index q is derived from the signature
/// length: q = (forscSig.length - 2212) / 16. FORS+C provides 112-bit security
/// even under accidental double-signing (r=2). Replay protection comes from
/// the EntryPoint nonce (4337) or Frame protocol nonce.
contract JardinAccount is BaseAccount {
    using ECDSA for bytes32;

    IEntryPoint private immutable _entryPoint;
    address public immutable c11Verifier;
    address public immutable forscVerifier;

    address public owner;
    bytes32 public masterPkSeed;
    bytes32 public masterPkRoot;

    /// @notice Sub-key slots: keccak256(r) => keccak256(subPkSeed, subPkRoot)
    mapping(bytes32 => bytes32) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotEntryPoint();

    constructor(
        IEntryPoint ep,
        address _owner,
        address _c11Verifier,
        address _forscVerifier,
        bytes32 _masterPkSeed,
        bytes32 _masterPkRoot
    ) {
        _entryPoint = ep;
        owner = _owner;
        c11Verifier = _c11Verifier;
        forscVerifier = _forscVerifier;
        masterPkSeed = _masterPkSeed;
        masterPkRoot = _masterPkRoot;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _requireForExecute() internal view override {
        require(msg.sender == address(entryPoint()), NotEntryPoint());
    }

    function rotateMasterKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotEntryPoint());
        masterPkSeed = newPkSeed;
        masterPkRoot = newPkRoot;
    }

    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotEntryPoint());
        require(newOwner != address(0));
        owner = newOwner;
    }

    /// @notice Validate hybrid signature: ECDSA + PQ on every UserOp.
    ///
    /// Signature layout (both types):
    ///   [type 1B][ecdsaSig 65B][...PQ payload...]
    ///
    /// Type 1 PQ payload: [r 32B][subPkSeed 16B][subPkRoot 16B][C11 sig ~4008B]
    /// Type 2 PQ payload: [H(r) 32B][subPkSeed 16B][subPkRoot 16B][FORS+C sig]
    ///   FORS+C sig length = 2212 + q*16; q derived by verifier from sig length.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        require(sig.length > 130, InvalidSignatureType());

        uint8 sigType = uint8(sig[0]);

        // ── ECDSA verification (required for all types) ──
        address recovered = userOpHash.recover(sig[1:66]);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        bytes calldata pq = sig[66:];

        if (sigType == 0x01) {
            // ── Type 1: ECDSA + C11 stateless + optional sub-key registration ──
            bytes32 r       = bytes32(pq[0:32]);
            bytes16 subSeed = bytes16(pq[32:48]);
            bytes16 subRoot = bytes16(pq[48:64]);

            (bool ok, bytes memory res) = c11Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    masterPkSeed, masterPkRoot, userOpHash, pq[64:]
                )
            );
            if (!ok || res.length < 32 || !abi.decode(res, (bool))) {
                return SIG_VALIDATION_FAILED;
            }

            if (r != bytes32(0)) {
                bytes32 key = keccak256(abi.encodePacked(r));
                require(slots[key] == bytes32(0), SlotAlreadyRegistered());
                slots[key] = keccak256(abi.encodePacked(subSeed, subRoot));
            }

        } else if (sigType == 0x02) {
            // ── Type 2: ECDSA + FORS+C compact ──
            // q is derived from signature length by the verifier.
            // No on-chain counter — FORS+C tolerates r=2 at 112-bit security.
            bytes32 key     = bytes32(pq[0:32]);
            bytes16 subSeed = bytes16(pq[32:48]);
            bytes16 subRoot = bytes16(pq[48:64]);

            require(
                keccak256(abi.encodePacked(subSeed, subRoot)) == slots[key],
                UnregisteredSlot()
            );

            (bool ok, bytes memory res) = forscVerifier.staticcall(
                abi.encodeWithSignature(
                    "verifyForsCUnbalanced(bytes32,bytes32,bytes32,bytes)",
                    bytes32(subSeed), bytes32(subRoot), userOpHash, pq[64:]
                )
            );
            if (!ok || res.length < 32 || !abi.decode(res, (bool))) {
                return SIG_VALIDATION_FAILED;
            }

        } else {
            revert InvalidSignatureType();
        }

        return SIG_VALIDATION_SUCCESS;
    }

    receive() external payable {}
}
