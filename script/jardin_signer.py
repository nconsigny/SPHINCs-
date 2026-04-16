#!/usr/bin/env python3
"""
JARDÍN signer — Judicious Authentication from Random-subset Domain-separated Indexed Nodes.

FORS+C few-time signatures under a balanced Merkle tree of height h=7.
Variant 2: k=26, a=5, n=16 bytes (128-bit). Q_MAX=128 leaves.

Usage:
    python3 script/jardin_signer.py <message_hex> [q_leaf]

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) as hex to stdout.
"""

import sys, struct, time
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Constants — Variant 2: k=26, a=5, balanced h=7
# ============================================================

N = 16
N_MASK = (1 << 256) - (1 << 128)
FULL = (1 << 256) - 1

K = 26        # FORS trees
A = 5         # FORS tree height (2^5 = 32 leaves per tree)
A_MASK = (1 << A) - 1  # 0x1F

MERKLE_H = 7          # balanced tree height
Q_MAX = 1 << MERKLE_H # 128

# FORS+C body (unchanged):
#   R(32) + counter(4) + (K-1)*(secret N + auth A*N) + lastRoot(N)
#   = 32 + 4 + 25*(16 + 5*16) + 16 = 2452
FORSC_BODY = 32 + 4 + (K - 1) * (N + A * N) + N  # 2452

# Full Type 2 FORS+C signature passed to verifier:
#   FORSC_BODY + q(1) + MERKLE_H * N = 2452 + 1 + 112 = 2565
FORSC_SIG_LEN = FORSC_BODY + 1 + MERKLE_H * N

ADRS_FORS_TREE = 3
ADRS_FORS_ROOTS = 4
ADRS_JARDIN_MERKLE = 16
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

# ============================================================
#  FORS+C (k=26, a=5)
# ============================================================

def build_jardin_fors_tree(seed, sk_seed, q, tree_idx):
    """FIPS 205 ADRS convention: kp=0, ci=q, x=treeHeight, y=continuous tree
    index across all k FORS trees. For tree_idx at height z with local node
    index p, global y = (tree_idx << (A - z)) | p."""
    n_leaves = 1 << A  # 32
    leaves = []
    for j in range(n_leaves):
        secret = jardin_fors_secret(sk_seed, q, tree_idx, j)
        global_y = (tree_idx << A) | j
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, global_y)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            global_y = (tree_idx << (A - h - 1)) | parent_idx
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, h + 1, global_y)
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
    # Last tree (t=K-1, leaf j=0): leaf ADRS x=0, y = (K-1) << A
    last_leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, (K - 1) << A)
    compress_vals.append(th(seed, last_leaf_adrs, roots[K - 1]))
    # FORS_ROOTS ADRS: kp=0, ci=q, x=0, y=0
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0)
    return th_multi(seed, roots_adrs, compress_vals)

# ============================================================
#  Balanced Merkle Tree (h=7, 128 leaves)
# ============================================================

def build_balanced_tree(seed, sk_seed):
    """Build balanced Merkle tree of Q_MAX=2^h FORS+C public keys.

    Returns (levels, root) where levels[L] is the list of nodes at level L.
    levels[MERKLE_H] = FORS+C public keys (leaves), levels[0] = [root].
    """
    fors_pks = []
    for q in range(1, Q_MAX + 1):
        eprint(f"  FORS+C PK q={q}/{Q_MAX}...")
        fors_pks.append(compute_forsc_pk(seed, sk_seed, q))

    levels = [None] * (MERKLE_H + 1)
    levels[MERKLE_H] = fors_pks
    for level in range(MERKLE_H - 1, -1, -1):
        layer = []
        child_layer = levels[level + 1]
        for i in range(1 << level):
            adrs = make_adrs(0, 0, ADRS_JARDIN_MERKLE, 0, 0, level, i)
            left = child_layer[2 * i]
            right = child_layer[2 * i + 1]
            layer.append(th_pair(seed, adrs, left, right))
        levels[level] = layer

    root = levels[0][0]
    return levels, root

def get_balanced_auth_path(levels, q):
    """Auth path for leaf q (1-indexed). Returns MERKLE_H=7 sibling nodes."""
    leaf_idx = q - 1
    auth = []
    idx = leaf_idx
    for j in range(MERKLE_H):
        # At step j we combine nodes at child level (MERKLE_H - j);
        # sibling is at levels[MERKLE_H - j][idx ^ 1].
        child_level = MERKLE_H - j
        auth.append(levels[child_level][idx ^ 1])
        idx >>= 1
    return auth

# ============================================================
#  Signing
# ============================================================

def jardin_grind_and_sign(seed, sk_seed, root, message, q):
    """Compute FORS+C body (2452 bytes) for leaf q."""
    R = keccak256(to_b32(sk_seed) + b"jardin_R" + to_b32(message) + to_b4(q))
    last_shift = (K - 1) * A  # 125

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

def jardin_sign(seed, sk_seed, root, levels, message, q):
    """Produce the full FORS+C compact signature (constant FORSC_SIG_LEN bytes)."""
    fors_body, R, counter, digest = jardin_grind_and_sign(
        seed, sk_seed, root, message, q
    )
    auth = get_balanced_auth_path(levels, q)
    sig = fors_body + bytes([q & 0xFF])
    for node in auth:
        sig += to_b32(node)[:N]
    assert len(sig) == FORSC_SIG_LEN, f"{len(sig)} != {FORSC_SIG_LEN}"
    return sig, R, counter, digest

# ============================================================
#  Local Verification
# ============================================================

def jardin_verify_locally(seed, root, message, sig):
    """Mirror the on-chain verifier for sanity checking."""
    assert len(sig) == FORSC_SIG_LEN, f"{len(sig)} != {FORSC_SIG_LEN}"

    R = int.from_bytes(sig[0:32], "big")
    counter = int.from_bytes(sig[32:36], "big")
    q = sig[FORSC_BODY]
    assert 1 <= q <= Q_MAX, f"q out of range: {q}"

    digest = jardin_h_msg(seed, root, R, message, counter)
    assert (digest >> ((K - 1) * A)) & A_MASK == 0
    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]

    off = 36
    tree_roots = []
    for t in range(K - 1):
        secret = int.from_bytes(sig[off:off + N], "big") << 128; off += N
        leaf_y = (t << A) | indices[t]
        node = th(seed, make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, leaf_y), secret)
        path_idx = indices[t]
        for h in range(A):
            sib = int.from_bytes(sig[off:off + N], "big") << 128; off += N
            pi = path_idx >> 1
            parent_y = (t << (A - h - 1)) | pi
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, 0, q, h + 1, parent_y)
            node = th_pair(seed, adrs, node, sib) if path_idx & 1 == 0 else th_pair(seed, adrs, sib, node)
            path_idx = pi
        tree_roots.append(node)

    lr = int.from_bytes(sig[off:off + N], "big") << 128
    tree_roots.append(th(seed, make_adrs(0, 0, ADRS_FORS_TREE, 0, q, 0, (K - 1) << A), lr))
    fors_pk = th_multi(seed, make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0), tree_roots)

    # Balanced Merkle walk
    leaf_idx = q - 1
    auth_off = FORSC_BODY + 1
    node = fors_pk
    for j in range(MERKLE_H):
        sibling = int.from_bytes(sig[auth_off + j * N:auth_off + (j + 1) * N], "big") << 128
        level = MERKLE_H - 1 - j
        parent_idx = leaf_idx >> (j + 1)
        adrs = make_adrs(0, 0, ADRS_JARDIN_MERKLE, 0, 0, level, parent_idx)
        if (leaf_idx >> j) & 1 == 0:
            node = th_pair(seed, adrs, node, sibling)
        else:
            node = th_pair(seed, adrs, sibling, node)

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
        eprint("Usage: python3 jardin_signer.py <message_hex> [q_leaf]")
        sys.exit(1)
    msg_hex = sys.argv[1].replace("0x", "")
    q_leaf = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    message_int = int(msg_hex, 16)

    t0 = time.time()
    pk_seed, sk_seed = jardin_derive_keys(message_int)
    eprint(f"  pkSeed = {hex(pk_seed)[:18]}...")
    eprint(f"  Building balanced tree (h={MERKLE_H}, Q_MAX={Q_MAX})...")
    levels, pk_root = build_balanced_tree(pk_seed, sk_seed)
    eprint(f"  pkRoot = {hex(pk_root)[:18]}...")

    assert 1 <= q_leaf <= Q_MAX
    eprint(f"  Signing at q={q_leaf}...")
    sig, _, _, _ = jardin_sign(pk_seed, sk_seed, pk_root, levels, message_int, q_leaf)
    jardin_verify_locally(pk_seed, pk_root, message_int, sig)

    eprint(f"  Signature: {len(sig)} bytes (constant)")
    eprint(f"  Total time: {time.time() - t0:.1f}s")
    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
