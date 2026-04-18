#!/usr/bin/env python3
"""
JARDINERO T0 signer — plain FORS + WOTS+C hypertree.

Parameters (T0_W+C_h14_d7_a6_k39):
    n=16, h=14, d=7, h'=2, a=6, k=39, w=16, l=32, swn=240
    q_s_budget = 2^13 = 8192 lifetime signatures @ 128-bit security

Designed to replace C11 as the onboarding-friendly slot-registration path
for JARDÍN 4337 accounts. Top-layer XMSS has only 4 WOTS+C keypairs
(h'=2), so keygen on hardware is ~40× faster than C11.

Signature layout (what gets passed to the verifier):
    [R (16)]
    [FORS secrets: K*N = 624]
    [FORS auth paths: K*A*N = 3744]
    [Hypertree: D*(4 + L*N + H'*N) = 7*548 = 3836]
    total: 16 + 624 + 3744 + 3836 = 8220 bytes

Usage:
    python3 script/jardin_t0_signer.py <master_sk_hex> <message_hex> [sig_counter]

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) hex on stdout.
"""

import sys, struct, hmac, hashlib, time
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Parameters — T0_W+C_h14_d7_a6_k39
# ============================================================

N         = 16              # hash truncation (128-bit)
H         = 14              # total hypertree height
D         = 7               # hypertree layers
H_PRIME   = 2               # per-layer XMSS height
A         = 6               # FORS tree height
K         = 39              # FORS trees
W         = 16              # Winternitz
L         = 32              # WOTS chains
SWN       = 240             # WOTS+C target digit sum
Q_BUDGET  = 1 << 13         # 8192

A_MASK       = (1 << A) - 1
H_PRIME_MASK = (1 << H_PRIME) - 1
H_MASK       = (1 << H) - 1
W_MASK       = W - 1
LOG_W        = 4

N_MASK = (1 << 256) - (1 << 128)
FULL   = (1 << 256) - 1

R_LEN         = N                                   # 16
FORS_SECRETS  = K * N                               # 624
FORS_AUTH     = K * A * N                           # 3744
FORS_BODY_LEN = FORS_SECRETS + FORS_AUTH            # 4368
HT_LAYER_LEN  = 4 + L * N + H_PRIME * N             # 548
HT_LEN        = D * HT_LAYER_LEN                    # 3836
SIG_LEN       = R_LEN + FORS_BODY_LEN + HT_LEN      # 8220

# ADRS types (per T0 spec §4)
ADRS_WOTS_HASH  = 0
ADRS_WOTS_PK    = 1
ADRS_TREE       = 2
ADRS_FORS_TREE  = 3
ADRS_FORS_ROOTS = 4

# T0 H_msg domain separator — distinct from C11's 0xFF..FF
DOMAIN_T0 = FULL - 1  # 0xFF..FE

# ============================================================
#  Hash primitives
# ============================================================

def keccak256(data: bytes) -> int:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")

def to_b32(v: int) -> bytes:
    return (v & FULL).to_bytes(32, "big")

def to_b4(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)

_BUF96  = bytearray(96)
_BUF128 = bytearray(128)

def _k3(a, b, c):
    _BUF96[ 0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256); h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _k4(a, b, c, d):
    _BUF128[  0:32 ] = a.to_bytes(32, "big")
    _BUF128[ 32:64 ] = b.to_bytes(32, "big")
    _BUF128[ 64:96 ] = c.to_bytes(32, "big")
    _BUF128[ 96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256); h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

def make_adrs(layer, tree, atype, kp, ci, x, y):
    return ((layer & 0xFFFFFFFF)         << 224 |
            (tree  & 0xFFFFFFFFFFFFFFFF) << 160 |
            (atype & 0xFFFFFFFF)         << 128 |
            (kp    & 0xFFFFFFFF)         <<  96 |
            (ci    & 0xFFFFFFFF)         <<  64 |
            (x     & 0xFFFFFFFF)         <<  32 |
            (y     & 0xFFFFFFFF))

def th(seed, adrs, inp):
    return _k3(seed, adrs, inp) & N_MASK

def th_pair(seed, adrs, left, right):
    return _k4(seed, adrs, left, right) & N_MASK

def th_multi(seed, adrs, vals):
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

def h_msg(seed, root, R, message):
    """H_msg: keccak(seed || root || R || message || DOMAIN_T0) — full 32B."""
    return keccak256(to_b32(seed) + to_b32(root) + to_b32(R) +
                     to_b32(message) + to_b32(DOMAIN_T0))

def set_x(adrs, x):
    """Set the x (chain position) field, bits 32..63."""
    return (adrs & (FULL ^ (0xFFFFFFFF << 32))) | ((x & 0xFFFFFFFF) << 32)

def chain_hash(seed, base_adrs, val, start_pos, steps):
    v = val
    for s in range(steps):
        v = _k3(seed, set_x(base_adrs, start_pos + s), v) & N_MASK
    return v

# ============================================================
#  Key derivation (BIP-39 → T0)
# ============================================================

def hmac512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()

def derive_t0_keys(master_sk: bytes):
    """Derive (sk_seed, sk_prf, pk_seed) from the 32-byte master secret.

    Each output is 128 bits, placed in the high bytes of a 256-bit int
    so downstream hashing sees `value || 16 zero bytes`.
    """
    def to_high(b16): return int.from_bytes(b16 + b"\x00" * 16, "big")
    sk_seed = to_high(hmac512(master_sk, b"JARDIN/T0/SKSEED")[:N])
    sk_prf  = to_high(hmac512(master_sk, b"JARDIN/T0/SKPRF" )[:N])
    pk_seed = to_high(hmac512(master_sk, b"JARDIN/T0/PKSEED")[:N])
    return sk_seed, sk_prf, pk_seed

def wots_secret(sk_seed, layer, tree, kp, chain_idx):
    data = to_b32(sk_seed) + b"t0_wots" + to_b4(layer) + to_b32(tree) + to_b4(kp) + to_b4(chain_idx)
    return keccak256(data) & N_MASK

def fors_secret(sk_seed, tree_idx, leaf_idx):
    data = to_b32(sk_seed) + b"t0_fors" + to_b4(tree_idx) + to_b4(leaf_idx)
    return keccak256(data) & N_MASK

# ============================================================
#  WOTS+C
# ============================================================

def wots_base_adrs(layer, tree, kp):
    return make_adrs(layer, tree, ADRS_WOTS_HASH, kp, 0, 0, 0)

def wots_set_chain(base_adrs, ci):
    """Set ci (bits 64..95) to `ci`, keeping everything else (including x=0)."""
    mask = FULL ^ (0xFFFFFFFF << 64)
    return (base_adrs & mask) | ((ci & 0xFFFFFFFF) << 64)

def wots_keygen(seed, sk_seed, layer, tree, kp):
    """Returns (sks_list_of_L, wots_pk)."""
    base = wots_base_adrs(layer, tree, kp)
    sks = []
    tops = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sks.append(sk_i)
        chain_adrs = wots_set_chain(base, i)
        tops.append(chain_hash(seed, chain_adrs, sk_i, 0, W - 1))
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    wots_pk = th_multi(seed, pk_adrs, tops)
    return sks, wots_pk

def wots_pk_from_sig(seed, sigma, layer, tree, kp, digits):
    """Verifier-side: given WOTS+C sigma and digits, compute the WOTS pk."""
    base = wots_base_adrs(layer, tree, kp)
    tops = []
    for i in range(L):
        chain_adrs = wots_set_chain(base, i)
        tops.append(chain_hash(seed, chain_adrs, sigma[i], digits[i], W - 1 - digits[i]))
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return th_multi(seed, pk_adrs, tops)

def wots_digest(seed, layer, tree, kp, msg_hash, counter):
    """keccak(seed || wotsAdrs || msg || counter). Returns full 256-bit int."""
    adrs = wots_base_adrs(layer, tree, kp)
    return _k4(seed, adrs, msg_hash, counter)

def extract_digits(d):
    return [(d >> (i * LOG_W)) & W_MASK for i in range(L)]

def wots_find_counter(seed, layer, tree, kp, msg_hash):
    for c in range(10_000_000):
        d = wots_digest(seed, layer, tree, kp, msg_hash, c)
        digits = extract_digits(d)
        if sum(digits) == SWN:
            return c, digits
    raise RuntimeError("WOTS+C counter grinding failed")

def wots_sign(seed, sks, layer, tree, kp, msg_hash):
    counter, digits = wots_find_counter(seed, layer, tree, kp, msg_hash)
    base = wots_base_adrs(layer, tree, kp)
    sigma = []
    for i in range(L):
        chain_adrs = wots_set_chain(base, i)
        sigma.append(chain_hash(seed, chain_adrs, sks[i], 0, digits[i]))
    return sigma, counter, digits

# ============================================================
#  XMSS tree (per layer, 4 leaves)
# ============================================================

def build_xmss_tree(seed, sk_seed, layer, tree):
    """Build one XMSS tree at (layer, tree). Returns (wots_sks_list, nodes, root)."""
    n_leaves = 1 << H_PRIME
    wots_sks = []
    leaves = []
    for kp in range(n_leaves):
        sks, pk = wots_keygen(seed, sk_seed, layer, tree, kp)
        wots_sks.append(sks)
        leaves.append(pk)
    nodes = [leaves]
    for h in range(H_PRIME):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return wots_sks, nodes, nodes[H_PRIME][0]

def xmss_auth_path(nodes, leaf_idx):
    path = []
    idx = leaf_idx
    for h in range(H_PRIME):
        path.append(nodes[h][idx ^ 1])
        idx >>= 1
    return path

# ============================================================
#  FORS (plain, no FORS+C)
# ============================================================

def build_fors_tree(seed, sk_seed, tree_idx):
    """Build one plain-FORS tree at tree_idx. Returns (nodes, root)."""
    n_leaves = 1 << A
    leaves = []
    for j in range(n_leaves):
        secret = fors_secret(sk_seed, tree_idx, j)
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, j)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[A][0]

def fors_sign(seed, sk_seed, digest):
    """Sign the k FORS indices drawn from the low bits of digest.

    Returns (secrets[K], auth_paths[K], fors_pk).
    """
    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]
    secrets = []
    auth_paths = []
    roots = []
    for t in range(K):
        eprint(f"  FORS tree {t+1}/{K}...")
        nodes, root = build_fors_tree(seed, sk_seed, t)
        secrets.append(fors_secret(sk_seed, t, indices[t]))
        auth_paths.append(xmss_auth_path_on(nodes, indices[t], A))
        roots.append(root)
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0)
    fors_pk = th_multi(seed, roots_adrs, roots)
    return secrets, auth_paths, fors_pk, indices

def xmss_auth_path_on(nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(nodes[h][idx ^ 1])
        idx >>= 1
    return path

# ============================================================
#  Top-layer root (keygen)
# ============================================================

def build_pk_root(seed, sk_seed):
    """pk_root = XMSS root at top layer L=D-1, tree=0. Only 4 WOTS keypairs."""
    _, _, root = build_xmss_tree(seed, sk_seed, D - 1, 0)
    return root

# ============================================================
#  Signing
# ============================================================

def derive_R(sk_prf, message, sig_counter):
    """Deterministic per-(message, counter) randomness."""
    return keccak256(to_b32(sk_prf) + b"t0_R" + to_b32(message) + to_b4(sig_counter)) & N_MASK

def t0_sign(seed, sk_seed, sk_prf, pk_root, message, sig_counter=0):
    R = derive_R(sk_prf, message, sig_counter)
    digest = h_msg(seed, pk_root, R, message)

    htIdx = (digest >> (K * A)) & H_MASK
    eprint(f"  digest = {hex(digest)[:18]}..., htIdx = {htIdx}")

    # FORS
    eprint("  Signing FORS...")
    fors_secrets, fors_auth_paths, fors_pk, _ = fors_sign(seed, sk_seed, digest)

    # Hypertree
    eprint("  Signing hypertree...")
    ht_layers = []
    current_node = fors_pk
    idx = htIdx
    for layer in range(D):
        idx_leaf = idx & H_PRIME_MASK
        idx_tree = idx >> H_PRIME

        eprint(f"    Layer {layer}: tree={idx_tree}, leaf={idx_leaf}")
        wots_sks, tree_nodes, _ = build_xmss_tree(seed, sk_seed, layer, idx_tree)
        sigma, counter, digits = wots_sign(seed, wots_sks[idx_leaf],
                                            layer, idx_tree, idx_leaf, current_node)
        auth = xmss_auth_path(tree_nodes, idx_leaf)
        ht_layers.append((sigma, counter, auth))

        # Walk up this layer to seed the next layer's message
        wots_pk_v = wots_pk_from_sig(seed, sigma, layer, idx_tree, idx_leaf, digits)
        node = wots_pk_v
        m_idx = idx_leaf
        for h in range(H_PRIME):
            sib = auth[h]
            pi = m_idx >> 1
            adrs = make_adrs(layer, idx_tree, ADRS_TREE, 0, 0, h + 1, pi)
            node = th_pair(seed, adrs, node, sib) if (m_idx & 1) == 0 else th_pair(seed, adrs, sib, node)
            m_idx = pi
        current_node = node
        idx = idx_tree

    assert current_node == pk_root, f"pk_root mismatch: {hex(current_node)} vs {hex(pk_root)}"

    # Serialize
    sig = to_b32(R)[:N]
    for sec in fors_secrets:
        sig += to_b32(sec)[:N]
    for path in fors_auth_paths:
        for node in path:
            sig += to_b32(node)[:N]
    for sigma, counter, auth in ht_layers:
        sig += to_b4(counter)
        for chain in sigma:
            sig += to_b32(chain)[:N]
        for node in auth:
            sig += to_b32(node)[:N]

    assert len(sig) == SIG_LEN, f"Sig length {len(sig)} != {SIG_LEN}"
    return sig

# ============================================================
#  Local verifier (mirrors planned on-chain Yul)
# ============================================================

def t0_verify(seed, pk_root, message, sig):
    assert len(sig) == SIG_LEN, f"len {len(sig)} != {SIG_LEN}"
    R = int.from_bytes(sig[0:16] + b"\x00" * 16, "big")
    digest = h_msg(seed, pk_root, R, message)

    indices = [(digest >> (t * A)) & A_MASK for t in range(K)]
    htIdx = (digest >> (K * A)) & H_MASK

    # FORS
    sec_off  = R_LEN
    auth_off = R_LEN + FORS_SECRETS
    roots = []
    for t in range(K):
        secret = int.from_bytes(sig[sec_off + t * N : sec_off + (t + 1) * N] + b"\x00" * 16, "big")
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, t, 0, 0, indices[t])
        node = th(seed, leaf_adrs, secret)
        path_idx = indices[t]
        for h in range(A):
            sib_bytes = sig[auth_off + t * A * N + h * N : auth_off + t * A * N + (h + 1) * N]
            sib = int.from_bytes(sib_bytes + b"\x00" * 16, "big")
            pi = path_idx >> 1
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, t, 0, h + 1, pi)
            if path_idx & 1 == 0:
                node = th_pair(seed, adrs, node, sib)
            else:
                node = th_pair(seed, adrs, sib, node)
            path_idx = pi
        roots.append(node)
    fors_pk = th_multi(seed, make_adrs(0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0), roots)

    # Hypertree
    ht_off = R_LEN + FORS_BODY_LEN
    current = fors_pk
    idx = htIdx
    for layer in range(D):
        idx_leaf = idx & H_PRIME_MASK
        idx_tree = idx >> H_PRIME

        base_off = ht_off + layer * HT_LAYER_LEN
        counter = int.from_bytes(sig[base_off : base_off + 4], "big")

        d = wots_digest(seed, layer, idx_tree, idx_leaf, current, counter)
        digits = extract_digits(d)
        if sum(digits) != SWN:
            raise AssertionError(f"Layer {layer}: digit sum {sum(digits)} != {SWN}")

        wots_off = base_off + 4
        sigma = []
        for i in range(L):
            v = int.from_bytes(sig[wots_off + i * N : wots_off + (i + 1) * N] + b"\x00" * 16, "big")
            sigma.append(v)
        wots_pk = wots_pk_from_sig(seed, sigma, layer, idx_tree, idx_leaf, digits)

        auth_off_L = wots_off + L * N
        node = wots_pk
        m_idx = idx_leaf
        for h in range(H_PRIME):
            sib = int.from_bytes(sig[auth_off_L + h * N : auth_off_L + (h + 1) * N] + b"\x00" * 16, "big")
            pi = m_idx >> 1
            adrs = make_adrs(layer, idx_tree, ADRS_TREE, 0, 0, h + 1, pi)
            node = th_pair(seed, adrs, node, sib) if (m_idx & 1) == 0 else th_pair(seed, adrs, sib, node)
            m_idx = pi
        current = node
        idx = idx_tree

    if current != pk_root:
        raise AssertionError(f"Root mismatch: {hex(current)} vs {hex(pk_root)}")
    return True

# ============================================================
#  CLI
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def abi_encode(seed, root, sig):
    enc = to_b32(seed) + to_b32(root) + to_b32(0x60) + to_b32(len(sig))
    enc += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return enc

def main():
    if len(sys.argv) < 3:
        eprint("Usage: python3 jardin_t0_signer.py <master_sk_hex> <message_hex> [sig_counter]")
        sys.exit(1)
    master_sk = bytes.fromhex(sys.argv[1].replace("0x", ""))
    if len(master_sk) != 32:
        eprint("master_sk must be 32 bytes"); sys.exit(1)
    message_hex = sys.argv[2].replace("0x", "")
    message_int = int(message_hex, 16)
    sig_counter = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    t0 = time.time()
    sk_seed, sk_prf, pk_seed = derive_t0_keys(master_sk)
    eprint(f"  pk_seed = {hex(pk_seed)[:18]}...")
    eprint(f"  Building top-layer XMSS (L={D-1}, {1 << H_PRIME} WOTS+C keypairs)...")
    pk_root = build_pk_root(pk_seed, sk_seed)
    eprint(f"  pk_root = {hex(pk_root)[:18]}...")

    eprint(f"  Signing at sig_counter={sig_counter}...")
    sig = t0_sign(pk_seed, sk_seed, sk_prf, pk_root, message_int, sig_counter)
    t0_verify(pk_seed, pk_root, message_int, sig)
    eprint(f"  Local verify OK. Sig: {len(sig)} bytes. Total: {time.time() - t0:.1f}s")

    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
