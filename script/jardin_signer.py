#!/usr/bin/env python3
"""
JARDÍN signer — Judicious Authentication from Random-subset Domain-separated Indexed Nodes.

FORS+C few-time signatures with unbalanced Merkle tree.
Variant 2: k=26, a=5, n=16 bytes (128-bit). Q_MAX=32 leaves.

Usage:
    python3 script/jardin_signer.py <message_hex> [q_leaf] [q_max]

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) as hex to stdout.
"""

import sys, struct, time
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Constants — Variant 2: k=26, a=5
# ============================================================

N = 16
N_MASK = (1 << 256) - (1 << 128)
FULL = (1 << 256) - 1

K = 26        # FORS trees
A = 5         # FORS tree height (2^5 = 32 leaves per tree)
A_MASK = (1 << A) - 1  # 0x1F
Q_MAX = 32

# Signature layout:
#   R(32) + counter(4) + (K-1)*(secret N + auth A*N) + lastRoot(N)
#   = 32 + 4 + 25*(16 + 5*16) + 16 = 32 + 4 + 25*96 + 16 = 2452
FORSC_BODY = 32 + 4 + (K - 1) * (N + A * N) + N  # 2452

ADRS_FORS_TREE = 3
ADRS_FORS_ROOTS = 4
ADRS_UNBALANCED = 6
HMSG_DOMAIN = (1 << 256) - 1

# ============================================================
#  Keccak256
# ============================================================

def keccak256(data: bytes) -> int:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")

def to_b32(val: int) -> bytes:
    return (val & FULL).to_bytes(32, "big")

def to_b4(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)

_BUF96 = bytearray(96)
_BUF128 = bytearray(128)

def _keccak_3x32(a, b, c):
    _BUF96[0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _keccak_4x32(a, b, c, d):
    _BUF128[0:32] = a.to_bytes(32, "big")
    _BUF128[32:64] = b.to_bytes(32, "big")
    _BUF128[64:96] = c.to_bytes(32, "big")
    _BUF128[96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

# ============================================================
#  Tweakable Hash
# ============================================================

def make_adrs(layer, tree, atype, kp, ci, cp, ha):
    return ((layer & 0xFFFFFFFF) << 224 |
            (tree & 0xFFFFFFFFFFFFFFFF) << 160 |
            (atype & 0xFFFFFFFF) << 128 |
            (kp & 0xFFFFFFFF) << 96 |
            (ci & 0xFFFFFFFF) << 64 |
            (cp & 0xFFFFFFFF) << 32 |
            (ha & 0xFFFFFFFF))

def th(seed, adrs, inp):
    return _keccak_3x32(seed, adrs, inp) & N_MASK

def th_pair(seed, adrs, left, right):
    return _keccak_4x32(seed, adrs, left, right) & N_MASK

def th_multi(seed, adrs, vals):
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

def jardin_h_msg(seed, root, R, message, counter):
    data = (to_b32(seed) + to_b32(root) + to_b32(R) +
            to_b32(message) + to_b32(counter) + to_b32(HMSG_DOMAIN))
    return keccak256(data)

# ============================================================
#  Key Derivation
# ============================================================

def jardin_derive_keys(entropy_int):
    sub_entropy = keccak256(b"jardin_sub_v1" + to_b32(entropy_int))
    pk_seed = keccak256(b"jardin_pk_seed" + to_b32(sub_entropy)) & N_MASK
    sk_seed = keccak256(b"jardin_sk_seed" + to_b32(sub_entropy))
    return pk_seed, sk_seed

def jardin_fors_secret(sk_seed, q, tree_idx, leaf_idx):
    data = to_b32(sk_seed) + b"jfors" + to_b4(q) + to_b4(tree_idx) + to_b4(leaf_idx)
    return keccak256(data) & N_MASK

def jardin_sentinel(seed, sk_seed):
    return keccak256(to_b32(seed) + to_b32(sk_seed) + b"jardin_sentinel") & N_MASK

# ============================================================
#  FORS+C (k=26, a=5)
# ============================================================

def build_jardin_fors_tree(seed, sk_seed, q, tree_idx):
    n_leaves = 1 << A  # 32
    leaves = []
    for j in range(n_leaves):
        secret = jardin_fors_secret(sk_seed, q, tree_idx, j)
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, q, 0, j)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, q, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[A][0]

def get_auth_path(tree_nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(tree_nodes[h][idx ^ 1])
        idx >>= 1
    return path

def compute_forsc_pk(seed, sk_seed, q):
    roots = []
    for t in range(K):
        _, root = build_jardin_fors_tree(seed, sk_seed, q, t)
        roots.append(root)
    compress_vals = list(roots[:K - 1])
    last_leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, K - 1, q, 0, 0)
    compress_vals.append(th(seed, last_leaf_adrs, roots[K - 1]))
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0)
    return th_multi(seed, roots_adrs, compress_vals)

# ============================================================
#  Unbalanced Merkle Tree (with sentinel)
# ============================================================

def build_unbalanced_tree(seed, sk_seed, q_max):
    D = q_max
    fors_pks = []
    for i in range(D):
        q = i + 1
        eprint(f"  FORS+C PK q={q}/{D}...")
        pk = compute_forsc_pk(seed, sk_seed, q)
        fors_pks.append(pk)

    sent = jardin_sentinel(seed, sk_seed)

    if D == 1:
        root = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, 0, 0), sent, fors_pks[0])
        return fors_pks, [], sent, root

    spine = [None] * (D - 1)
    spine[D - 2] = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, D - 1, 0),
                            sent, fors_pks[D - 1])
    for i in range(D - 3, -1, -1):
        spine[i] = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, i + 1, 0),
                           spine[i + 1], fors_pks[i + 1])
    root = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, 0, 0),
                   spine[0], fors_pks[0])
    return fors_pks, spine, sent, root

def get_unbalanced_auth_path(fors_pks, spine, sentinel, q, q_max):
    D = q_max
    i = q - 1
    if D == 1:
        return [sentinel]
    auth = []
    if i == 0:
        auth.append(spine[0])
    elif i >= D - 1:
        auth.append(sentinel)
    else:
        auth.append(spine[i])
    for j in range(i - 1, -1, -1):
        auth.append(fors_pks[j])
    assert len(auth) == q
    return auth

# ============================================================
#  Signing
# ============================================================

def jardin_grind_and_sign(seed, sk_seed, root, message, q):
    R = keccak256(to_b32(sk_seed) + b"jardin_R" + to_b32(message) + to_b4(q))
    last_shift = (K - 1) * A  # 25 * 5 = 125

    for counter in range(10_000_000):
        digest = jardin_h_msg(seed, root, R, message, counter)
        if (digest >> last_shift) & A_MASK == 0:
            eprint(f"  Grind: counter={counter}")
            break
    else:
        raise RuntimeError("Grinding failed")

    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]
    assert indices[K - 1] == 0

    secrets = []
    auth_paths_fors = []
    for t in range(K - 1):
        tree_nodes, _ = build_jardin_fors_tree(seed, sk_seed, q, t)
        secrets.append(jardin_fors_secret(sk_seed, q, t, indices[t]))
        auth_paths_fors.append(get_auth_path(tree_nodes, indices[t], A))

    _, last_root = build_jardin_fors_tree(seed, sk_seed, q, K - 1)

    sig = to_b32(R) + to_b4(counter)
    for t in range(K - 1):
        sig += to_b32(secrets[t])[:N]
        for node in auth_paths_fors[t]:
            sig += to_b32(node)[:N]
    sig += to_b32(last_root)[:N]

    assert len(sig) == FORSC_BODY, f"{len(sig)} != {FORSC_BODY}"
    return sig, R, counter, digest

# ============================================================
#  Local Verification
# ============================================================

def jardin_verify_locally(seed, root, message, q, R, counter, digest,
                          fors_sig, fors_pks, spine, sentinel, q_max):
    d2 = jardin_h_msg(seed, root, R, message, counter)
    assert d2 == digest
    assert (digest >> ((K - 1) * A)) & A_MASK == 0
    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]

    off = 36
    tree_roots = []
    for t in range(K - 1):
        secret = int.from_bytes(fors_sig[off:off + N], "big") << 128; off += N
        node = th(seed, make_adrs(0, 0, ADRS_FORS_TREE, t, q, 0, indices[t]), secret)
        path_idx = indices[t]
        for h in range(A):
            sib = int.from_bytes(fors_sig[off:off + N], "big") << 128; off += N
            pi = path_idx >> 1
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, t, q, h + 1, pi)
            node = th_pair(seed, adrs, node, sib) if path_idx & 1 == 0 else th_pair(seed, adrs, sib, node)
            path_idx = pi
        tree_roots.append(node)

    lr = int.from_bytes(fors_sig[off:off + N], "big") << 128
    tree_roots.append(th(seed, make_adrs(0, 0, ADRS_FORS_TREE, K - 1, q, 0, 0), lr))
    fors_pk = th_multi(seed, make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0), tree_roots)

    auth = get_unbalanced_auth_path(fors_pks, spine, sentinel, q, q_max)
    node = fors_pk
    node = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, q - 1, 0), auth[0], node)
    for j in range(1, len(auth)):
        node = th_pair(seed, make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, q - 1 - j, 0), node, auth[j])
    assert node == root, f"Root mismatch: {hex(node)} != {hex(root)}"
    eprint("  Local verification OK")

# ============================================================
#  Utility & Main
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def abi_encode(seed, root, sig):
    encoded = to_b32(seed) + to_b32(root) + to_b32(0x60) + to_b32(len(sig))
    encoded += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return encoded

def main():
    if len(sys.argv) < 2:
        eprint("Usage: python3 jardin_signer.py <message_hex> [q_leaf] [q_max]")
        sys.exit(1)
    msg_hex = sys.argv[1].replace("0x", "")
    q_leaf = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    q_max = int(sys.argv[3]) if len(sys.argv) > 3 else Q_MAX
    message_int = int(msg_hex, 16)

    t0 = time.time()
    pk_seed, sk_seed = jardin_derive_keys(message_int)
    eprint(f"  pkSeed = {hex(pk_seed)[:18]}...")
    eprint(f"  Building unbalanced tree (Q_MAX={q_max})...")
    fors_pks, spine, sent, pk_root = build_unbalanced_tree(pk_seed, sk_seed, q_max)
    eprint(f"  pkRoot = {hex(pk_root)[:18]}...")

    assert 1 <= q_leaf <= q_max
    eprint(f"  Signing at q={q_leaf}...")
    fors_sig, R, counter, digest = jardin_grind_and_sign(pk_seed, sk_seed, pk_root, message_int, q_leaf)
    unb_auth = get_unbalanced_auth_path(fors_pks, spine, sent, q_leaf, q_max)
    jardin_verify_locally(pk_seed, pk_root, message_int, q_leaf, R, counter, digest,
                          fors_sig, fors_pks, spine, sent, q_max)

    sig = fors_sig
    for node in unb_auth:
        sig += to_b32(node)[:N]
    expected = FORSC_BODY + q_leaf * N
    assert len(sig) == expected, f"{len(sig)} != {expected}"
    eprint(f"  Signature: {len(sig)} bytes ({q_leaf} auth nodes)")
    eprint(f"  Total time: {time.time() - t0:.1f}s")
    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
