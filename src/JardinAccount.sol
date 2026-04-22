// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title JardinAccount — Hybrid ECDSA + JARDÍN SPX ERC-4337 account
/// @notice Every UserOp requires ECDSA + post-quantum signature.
///
///   Type 1 (0x01): ECDSA + SPX (plain SPHINCS+, slot-registration + stateless fallback)
///   Type 2 (0x02): ECDSA + FORS+C compact via registered sub-key slot
///   Type 3 (0x03): ECDSA + C11 (optional recovery; only if c11Verifier set)
///
/// SPX parameters: n=16, h=20, d=5, h'=4, a=7, k=20, w=8, l=45, plain WOTS+ checksum.
/// Signature length: 6512 B. Signing cost: ~36.6K keccak calls (fast on SE hardware).
/// A C11 verifier may be attached post-deployment via attachC11Recovery for
/// break-glass scenarios — never used during normal operation.
///
/// Slot key is keccak256(subPkSeed, subPkRoot) — the sub-key's public
/// commitment. The random `r` used to derive the sub-key never appears
/// on-chain.
contract JardinAccount is BaseAccount {
    using ECDSA for bytes32;

    IEntryPoint private immutable _entryPoint;
    address public immutable spxVerifier;
    address public immutable forscVerifier;

    address public owner;
    bytes32 public spxPkSeed;
    bytes32 public spxPkRoot;

    /// @notice Optional C11 recovery verifier. Zero until attached.
    address public c11Verifier;
    bytes32 public c11PkSeed;
    bytes32 public c11PkRoot;

    /// @notice Sub-key slots: keccak256(subPkSeed, subPkRoot) => 1 (registered flag)
    mapping(bytes32 => uint256) public slots;

    error InvalidSignatureType();
    error SlotAlreadyRegistered();
    error UnregisteredSlot();
    error NotEntryPoint();
    error RecoveryAlreadySet();
    error RecoveryNotConfigured();

    constructor(
        IEntryPoint ep,
        address _owner,
        address _spxVerifier,
        address _forscVerifier,
        bytes32 _spxPkSeed,
        bytes32 _spxPkRoot
    ) {
        _entryPoint = ep;
        owner = _owner;
        spxVerifier = _spxVerifier;
        forscVerifier = _forscVerifier;
        spxPkSeed = _spxPkSeed;
        spxPkRoot = _spxPkRoot;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _requireForExecute() internal view override {
        require(msg.sender == address(entryPoint()), NotEntryPoint());
    }

    function rotateSpxKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotEntryPoint());
        spxPkSeed = newPkSeed;
        spxPkRoot = newPkRoot;
    }

    function rotateOwner(address newOwner) external {
        require(msg.sender == address(this), NotEntryPoint());
        require(newOwner != address(0));
        owner = newOwner;
    }

    /// @notice Attach a C11 recovery verifier. Callable only via self-call
    ///         (i.e., from a validated UserOp).  One-shot: once set, the
    ///         keys can still be rotated but the verifier address is fixed.
    function attachC11Recovery(address verifier, bytes32 pkSeed, bytes32 pkRoot) external {
        require(msg.sender == address(this), NotEntryPoint());
        require(c11Verifier == address(0), RecoveryAlreadySet());
        require(verifier != address(0));
        c11Verifier = verifier;
        c11PkSeed = pkSeed;
        c11PkRoot = pkRoot;
    }

    function rotateC11RecoveryKeys(bytes32 newPkSeed, bytes32 newPkRoot) external {
        require(msg.sender == address(this), NotEntryPoint());
        require(c11Verifier != address(0), RecoveryNotConfigured());
        c11PkSeed = newPkSeed;
        c11PkRoot = newPkRoot;
    }

    /// @notice Validate hybrid signature: ECDSA + PQ on every UserOp.
    ///
    /// Signature layout (all types):
    ///   [type 1B][ecdsaSig 65B][...PQ payload...]
    ///
    /// Type 1 PQ payload: [subPkSeed 16B][subPkRoot 16B][SPX sig 6512B]
    ///   subSeed==0 && subRoot==0 ⇒ stateless fallback (skip registration).
    /// Type 2 PQ payload: [subPkSeed 16B][subPkRoot 16B][FORS+C sig]
    /// Type 3 PQ payload: [C11 sig 3976B]  — uses c11PkSeed/c11PkRoot
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        require(sig.length > 66, InvalidSignatureType());

        uint8 sigType = uint8(sig[0]);

        // ── ECDSA verification (required for all types) ──
        address recovered = userOpHash.recover(sig[1:66]);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }

        bytes calldata pq = sig[66:];

        if (sigType == 0x01) {
            // ── Type 1: ECDSA + SPX (primary slot-registration path) ──
            require(pq.length >= 32, InvalidSignatureType());
            bytes16 subSeed = bytes16(pq[0:16]);
            bytes16 subRoot = bytes16(pq[16:32]);

            (bool ok, bytes memory res) = spxVerifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    spxPkSeed, spxPkRoot, userOpHash, pq[32:]
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
            require(pq.length >= 32, InvalidSignatureType());
            bytes16 subSeed = bytes16(pq[0:16]);
            bytes16 subRoot = bytes16(pq[16:32]);

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

        } else if (sigType == 0x03) {
            // ── Type 3: ECDSA + C11 optional recovery ──
            require(c11Verifier != address(0), RecoveryNotConfigured());

            (bool ok, bytes memory res) = c11Verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes32,bytes32,bytes32,bytes)",
                    c11PkSeed, c11PkRoot, userOpHash, pq
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
