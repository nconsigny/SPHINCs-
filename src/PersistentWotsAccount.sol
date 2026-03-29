// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./TweakableHash.sol";

/// @title PersistentWotsAccount
/// @notice ERC-4337 account backed by a Merkle root of 512 WOTS+C public keys.
/// @dev Each UserOperation consumes one leaf index via the EntryPoint nonce sequence.
///      This version fixes h=9, so a single root authorizes 512 transactions.
contract PersistentWotsAccount is BaseAccount {
    uint256 public constant TREE_HEIGHT = 9;
    uint256 public constant MAX_LEAVES = 1 << TREE_HEIGHT;

    uint256 private constant W = 16;
    uint256 private constant L = 32;
    uint256 private constant TARGET_SUM = 240;
    uint256 private constant WOTS_SIG_BYTES = 32 * 16 + 4;
    uint256 private constant AUTH_PATH_BYTES = TREE_HEIGHT * 16;
    uint256 private constant SIGNATURE_BYTES = WOTS_SIG_BYTES + AUTH_PATH_BYTES;
    uint256 private constant N_MASK =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000;

    IEntryPoint private immutable _entryPoint;
    bytes32 private _pkSeed;
    bytes32 private _pkRoot;

    constructor(IEntryPoint ep, bytes32 pkSeed_, bytes32 pkRoot_) {
        _entryPoint = ep;
        _pkSeed = pkSeed_;
        _pkRoot = pkRoot_;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function pkSeed() external view returns (bytes32) {
        return _pkSeed;
    }

    function pkRoot() external view returns (bytes32) {
        return _pkRoot;
    }

    function _requireForExecute() internal view override {
        require(msg.sender == address(entryPoint()), "PersistentWots: only entrypoint");
    }

    function _validateNonce(uint256 nonce) internal pure override {
        require(nonce < MAX_LEAVES, "PersistentWots: nonce out of range");
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 validationData) {
        if (_verifySignature(userOp.signature, userOpHash, userOp.nonce)) {
            return 0;
        }
        return 1;
    }

    function _verifySignature(
        bytes calldata signature,
        bytes32 userOpHash,
        uint256 leafIndex
    ) private view returns (bool) {
        if (signature.length != SIGNATURE_BYTES) {
            return false;
        }

        bytes32[] memory sigma = new bytes32[](L);
        bytes32[] memory pkElements = new bytes32[](L);
        bytes32 seed = _pkSeed;

        for (uint256 i = 0; i < L; i++) {
            bytes32 word;
            assembly ("memory-safe") {
                word := calldataload(add(signature.offset, mul(i, 16)))
            }
            sigma[i] = bytes32(uint256(word) & N_MASK);
        }

        uint256 count;
        assembly ("memory-safe") {
            count := shr(224, calldataload(add(signature.offset, 512)))
        }

        bytes32 digest;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, seed)
            mstore(add(m, 0x20), 0)
            mstore(add(m, 0x40), userOpHash)
            mstore(add(m, 0x60), count)
            digest := keccak256(m, 0x80)
        }

        uint256 digitSum = 0;
        for (uint256 i = 0; i < L; i++) {
            uint256 digit = (uint256(digest) >> (i * 4)) & 0xF;
            digitSum += digit;
            pkElements[i] = TweakableHash.chainHash(
                seed,
                TweakableHash.setChainIndex(bytes32(0), uint32(i)),
                sigma[i],
                digit,
                W - 1 - digit
            );
        }

        if (digitSum != TARGET_SUM) {
            return false;
        }

        bytes32 node = TweakableHash.thMulti(
            seed,
            TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_WOTS_PK, 0, 0, 0, 0),
            pkElements
        );

        bytes32 treeAdrs = TweakableHash.makeAdrs(0, 0, TweakableHash.ADRS_TREE, 0, 0, 0, 0);
        uint256 idx = leafIndex;

        for (uint256 level = 0; level < TREE_HEIGHT; level++) {
            bytes32 siblingWord;
            assembly ("memory-safe") {
                siblingWord := calldataload(add(add(signature.offset, 516), mul(level, 16)))
            }
            bytes32 sibling = bytes32(uint256(siblingWord) & N_MASK);

            treeAdrs = TweakableHash.setTreeHeight(treeAdrs, uint32(level + 1));
            treeAdrs = TweakableHash.setTreeIndex(treeAdrs, uint32(idx >> 1));

            if ((idx & 1) == 0) {
                node = TweakableHash.thPair(seed, treeAdrs, node, sibling);
            } else {
                node = TweakableHash.thPair(seed, treeAdrs, sibling, node);
            }
            idx >>= 1;
        }

        return node == _pkRoot;
    }

    receive() external payable {}
}
