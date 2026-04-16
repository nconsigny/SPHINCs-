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
/// Slot key is keccak256(subPkSeed, subPkRoot) — the sub-key's public commitment.
/// The random `r` used to derive the sub-key never appears on-chain.
///
/// No on-chain leaf counter. The leaf index q is encoded as a single byte
/// inside the FORS+C compact signature and verified via the balanced Merkle
/// tree walk. FORS+C provides 105-bit security even under accidental
/// double-signing (r=2). Replay protection comes from the EntryPoint nonce
/// (4337) or Frame protocol nonce.
contract JardinAccount is BaseAccount {
    using ECDSA for bytes32;

    IEntryPoint private immutable _entryPoint;
    address public immutable c11Verifier;
    address public immutable forscVerifier;

    address public owner;
    bytes32 public masterPkSeed;
    bytes32 public masterPkRoot;

    /// @notice Sub-key slots: keccak256(subPkSeed, subPkRoot) => 1 (registered flag)
    mapping(bytes32 => uint256) public slots;

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
    /// Type 1 PQ payload: [subPkSeed 16B][subPkRoot 16B][C11 sig ~4008B]
    ///   subSeed==0 && subRoot==0 ⇒ stateless fallback (skip registration).
    /// Type 2 PQ payload: [subPkSeed 16B][subPkRoot 16B][FORS+C sig 2565B]
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        require(sig.length > 98, InvalidSignatureType());

        uint8 sigType = uint8(sig[0]);

        // ── ECDSA verification (required for all types) ──
        address recovered = userOpHash.recover(sig[1:66]);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        bytes calldata pq = sig[66:];
        bytes16 subSeed = bytes16(pq[0:16]);
        bytes16 subRoot = bytes16(pq[16:32]);

        if (sigType == 0x01) {
            // ── Type 1: ECDSA + C11 stateless + optional sub-key registration ──
            (bool ok, bytes memory res) = c11Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    masterPkSeed, masterPkRoot, userOpHash, pq[32:]
                )
            );
            if (!ok || res.length < 32 || !abi.decode(res, (bool))) {
                return SIG_VALIDATION_FAILED;
            }

            if (subSeed != bytes16(0) || subRoot != bytes16(0)) {
                bytes32 key = keccak256(abi.encodePacked(subSeed, subRoot));
                require(slots[key] == 0, SlotAlreadyRegistered());
                slots[key] = 1;
            }

        } else if (sigType == 0x02) {
            // ── Type 2: ECDSA + FORS+C compact ──
            // q is encoded as a 1-byte field inside the FORS+C signature.
            // No on-chain counter — FORS+C tolerates r=2 at 105-bit security.
            bytes32 key = keccak256(abi.encodePacked(subSeed, subRoot));
            require(slots[key] != 0, UnregisteredSlot());

            (bool ok, bytes memory res) = forscVerifier.staticcall(
                abi.encodeWithSignature(
                    "verifyForsC(bytes32,bytes32,bytes32,bytes)",
                    bytes32(subSeed), bytes32(subRoot), userOpHash, pq[32:]
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
