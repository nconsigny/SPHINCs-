#!/usr/bin/env python3
"""
Persistent h=9 WOTS+C signer for the PersistentWotsAccount contract.

Usage:
    python3 script/persistent_wots_h9_signer.py keygen <entropy_hex>
        Output: ABI-encoded (bytes32 pkSeed, bytes32 pkRoot) as hex

    python3 script/persistent_wots_h9_signer.py sign <entropy_hex> <leaf_index> <message_hex>
        Output: ABI-encoded (bytes32 pkSeed, bytes32 pkRoot, bytes sig) as hex

Signature format:
    32 WOTS chain values (16 bytes each)
    + 4-byte count
    + 9 Merkle siblings (16 bytes each)
    = 660 bytes total
"""

import struct
import sys

from wots_ots_signer import (
    L,
    N_MASK,
    _keccak_4x32,
    keccak256,
    to_b4,
    to_b32,
    wots_keygen,
    wots_sign,
    wots_verify,
)

TREE_HEIGHT = 9
MAX_LEAVES = 1 << TREE_HEIGHT
SIGNATURE_BYTES = 516 + TREE_HEIGHT * 16
ADRS_TREE = 2


def derive_master_keys(entropy_int: int) -> tuple[int, int]:
    ent = keccak256(b"persistent_wots_h9_v1" + to_b32(entropy_int))
    seed = keccak256(b"pk_seed" + to_b32(ent)) & N_MASK
    master_sk_seed = keccak256(b"sk_seed" + to_b32(ent))
    return seed, master_sk_seed


def derive_leaf_sk_seed(master_sk_seed: int, leaf_index: int) -> int:
    return keccak256(to_b32(master_sk_seed) + b"leaf" + to_b4(leaf_index))


def th_pair(seed: int, adrs: int, left: int, right: int) -> int:
    return _keccak_4x32(seed, adrs, left, right) & N_MASK


def tree_adrs(height: int, index: int) -> int:
    return (ADRS_TREE << 128) | ((height & 0xFFFFFFFF) << 32) | (index & 0xFFFFFFFF)


def build_tree(seed: int, master_sk_seed: int) -> list[list[int]]:
    leaves = []
    for leaf_index in range(MAX_LEAVES):
        leaf_sk_seed = derive_leaf_sk_seed(master_sk_seed, leaf_index)
        leaves.append(wots_keygen(seed, leaf_sk_seed))

    levels = [leaves]
    current = leaves
    for height in range(1, TREE_HEIGHT + 1):
        nxt = []
        for i in range(0, len(current), 2):
            nxt.append(th_pair(seed, tree_adrs(height, i // 2), current[i], current[i + 1]))
        levels.append(nxt)
        current = nxt
    return levels


def build_auth_path(levels: list[list[int]], leaf_index: int) -> list[int]:
    idx = leaf_index
    path = []
    for height in range(TREE_HEIGHT):
        path.append(levels[height][idx ^ 1])
        idx >>= 1
    return path


def keygen(entropy_int: int) -> tuple[int, int]:
    seed, master_sk_seed = derive_master_keys(entropy_int)
    levels = build_tree(seed, master_sk_seed)
    return seed, levels[-1][0]


def sign_for_leaf(entropy_int: int, leaf_index: int, message_int: int) -> tuple[int, int, bytes]:
    if leaf_index < 0 or leaf_index >= MAX_LEAVES:
        raise ValueError(f"leaf_index {leaf_index} out of range")

    seed, master_sk_seed = derive_master_keys(entropy_int)
    levels = build_tree(seed, master_sk_seed)
    root = levels[-1][0]

    leaf_sk_seed = derive_leaf_sk_seed(master_sk_seed, leaf_index)
    leaf_sig = wots_sign(seed, leaf_sk_seed, message_int)
    leaf_pk = wots_keygen(seed, leaf_sk_seed)

    assert wots_verify(seed, leaf_pk, message_int, leaf_sig), "Leaf self-verification failed"

    auth_path = build_auth_path(levels, leaf_index)

    node = leaf_pk
    idx = leaf_index
    for height, sibling in enumerate(auth_path, start=1):
        adrs = tree_adrs(height, idx >> 1)
        if idx & 1 == 0:
            node = th_pair(seed, adrs, node, sibling)
        else:
            node = th_pair(seed, adrs, sibling, node)
        idx >>= 1
    assert node == root, "Merkle auth path reconstruction failed"

    sig = leaf_sig + b"".join(to_b32(sibling)[:16] for sibling in auth_path)
    assert len(sig) == SIGNATURE_BYTES, f"sig size {len(sig)} != {SIGNATURE_BYTES}"
    return seed, root, sig


def abi_encode_keygen(seed: int, root: int) -> bytes:
    return to_b32(seed) + to_b32(root)


def abi_encode_sign(seed: int, root: int, sig: bytes) -> bytes:
    out = to_b32(seed)
    out += to_b32(root)
    out += to_b32(96)
    out += to_b32(len(sig))
    if len(sig) % 32 != 0:
        sig += b"\x00" * (32 - len(sig) % 32)
    out += sig
    return out


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: persistent_wots_h9_signer.py keygen <entropy_hex>", file=sys.stderr)
        print("       persistent_wots_h9_signer.py sign <entropy_hex> <leaf_index> <message_hex>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "keygen":
        entropy = int(sys.argv[2], 16)
        seed, root = keygen(entropy)
        print("0x" + abi_encode_keygen(seed, root).hex())
        return

    if cmd == "sign":
        entropy = int(sys.argv[2], 16)
        leaf_index = int(sys.argv[3], 0)
        message = int(sys.argv[4], 16)
        seed, root, sig = sign_for_leaf(entropy, leaf_index, message)
        print("0x" + abi_encode_sign(seed, root, sig).hex())
        return

    print(f"Unknown command: {cmd}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
