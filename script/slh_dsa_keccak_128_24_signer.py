#!/usr/bin/env python3
"""
SLH-DSA-Keccak-128-24 signer (JARDIN-style Keccak variant).

Implements the NIST SP 800-230 SLH-DSA-*-128-24 parameter set with the
JARDIN family conventions (32-byte ADRS, keccak256 truncated to 16B,
LSB-first digest parsing).  Pairs with src/SLH-DSA-keccak-128-24verifier.sol.

Parameters:
    n  = 16     128-bit security
    h  = 22     total hypertree height
    d  = 1      single XMSS layer (no hypertree)
    h' = 22     2^22 leaves
    a  = 24     FORS tree height (2^24 leaves per tree)
    k  = 6      FORS trees
    w  = 4      Winternitz (lgw=2)
    R  = 16 B   per-signature randomness (on wire)

Hash primitives (all keccak256 truncated to 16B):
    F     keccak(seed32 ‖ adrs32 ‖ M32)                      96 B
    H     keccak(seed32 ‖ adrs32 ‖ L32 ‖ R32)               128 B
    T_l   keccak(seed32 ‖ adrs32 ‖ v0..v_l-1 × 32B)      variable
    Hmsg  keccak(seed32 ‖ root32 ‖ R32 ‖ msg32 ‖ 0xFF..FB)  160 B

Signature layout (3,856 B):
    R(16) | FORS = 6 × (sk 16 + auth 24·16) = 2,400 |
                  HT = 1 × (WOTS 68·16 + auth 22·16) = 1,440

NOTE on key generation:  d=1, h=22 means the XMSS public key is the root
of a 2^22-leaf tree.  Building it naively requires ~4M WOTS+ keygens
(≈300M F calls) which is slow in Python (~tens of minutes).  For dev
iteration the script accepts `--height N` to override h' (with the same
override applied symmetrically in the local verify mirror — but signatures
produced under a non-NIST height will NOT verify against the on-chain
contract, which hardcodes h=h'=22).

Usage:
    python3 script/slh_dsa_keccak_128_24_signer.py <master_sk_hex> <message_hex> \\
        [sig_counter] [--height N]

Output:  ABI-encoded (bytes32 seed, bytes32 root, bytes sig) hex on stdout.
"""

import sys, os, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jardin_primitives import (
    keccak256, to_b32, to_b4,
    make_adrs, th, th_pair, th_multi,
    ADRS_WOTS_HASH, ADRS_WOTS_PK, ADRS_XMSS_TREE, ADRS_FORS_TREE, ADRS_FORS_ROOTS,
    N, N_MASK, FULL, hmac512,
)

# ============================================================
#  Parameters (NIST SP 800-230 SLH-DSA-*-128-24)
# ============================================================

H_DEFAULT  = 22
D          = 1
A          = 24
K          = 6
W          = 4
LOG_W      = 2
L1         = 64
L2         = 4
L          = 68
R_LEN      = 16     # NIST: R is n bytes on wire

A_MASK     = (1 << A) - 1
W_MASK     = W - 1

HMSG_DOMAIN_KECCAK_128_24 = FULL - 4    # 0xFF..FB

# ============================================================
#  Hash primitives
# ============================================================

def F(seed, adrs, M):
    return th(seed, adrs, M)

def H_(seed, adrs, left, right):
    return th_pair(seed, adrs, left, right)

def T_l(seed, adrs, vals):
    return th_multi(seed, adrs, vals)

def T_k(seed, adrs, roots):
    return th_multi(seed, adrs, roots)

def h_msg(seed, root, R, message):
    return keccak256(to_b32(seed) + to_b32(root) + to_b32(R) +
                     to_b32(message) + to_b32(HMSG_DOMAIN_KECCAK_128_24))

# ============================================================
#  Digest parsing (LSB-first, JARDIN family)
# ============================================================

def digest_indices(d_int: int, h_param: int, a_param: int = A):
    a_mask = (1 << a_param) - 1
    md = [(d_int >> (a_param * t)) & a_mask for t in range(K)]
    leaf_idx = (d_int >> (K * a_param)) & ((1 << h_param) - 1)
    return md, leaf_idx

# ============================================================
#  WOTS+ checksum (plain SLH-DSA)
# ============================================================

def base_w_node(node_int: int):
    """Extract 64 base-w=4 digits (LSB-first) from the 128-bit node value
    sitting in the high 16 bytes of node_int (low 16 bytes zeroed)."""
    v = node_int >> 128
    return [(v >> (LOG_W * i)) & W_MASK for i in range(L1)]

def wots_checksum(msg_digits):
    assert len(msg_digits) == L1
    csum = sum((W - 1) - d for d in msg_digits)
    # l2·lgw = 8 bits ⇒ already byte-aligned, no pre-shift.
    return [(csum >> (6 - LOG_W * j)) & W_MASK for j in range(L2)]

def wots_digits(node_int):
    md = base_w_node(node_int)
    return md + wots_checksum(md)

# ============================================================
#  Key derivation (BIP-39 style, identical pattern to SPX signer)
# ============================================================

def derive_keys(master_sk: bytes):
    def to_high(b16):
        return int.from_bytes(b16 + b"\x00" * 16, "big")
    sk_seed = to_high(hmac512(master_sk, b"JARDIN/SLHK128_24/SKSEED")[:N])
    sk_prf  = to_high(hmac512(master_sk, b"JARDIN/SLHK128_24/SKPRF" )[:N])
    pk_seed = to_high(hmac512(master_sk, b"JARDIN/SLHK128_24/PKSEED")[:N])
    return sk_seed, sk_prf, pk_seed

def wots_secret(sk_seed, layer, tree, kp, chain_idx):
    data = (to_b32(sk_seed) + b"slhk_wots" + to_b4(layer) +
            tree.to_bytes(8, "big") + to_b4(kp) + to_b4(chain_idx))
    return keccak256(data) & N_MASK

def fors_secret(sk_seed, fors_t, leaf_idx_within_tree):
    data = (to_b32(sk_seed) + b"slhk_fors" + to_b4(fors_t) +
            to_b4(leaf_idx_within_tree))
    return keccak256(data) & N_MASK

def derive_R(sk_prf, message, sig_counter):
    return keccak256(to_b32(sk_prf) + b"slhk_R" + to_b32(message) +
                     to_b4(sig_counter)) & N_MASK

# ============================================================
#  WOTS+
# ============================================================

def wots_chain(seed, layer, tree, kp, chain_i, x_start, steps, val):
    v = val
    for s in range(steps):
        adrs = make_adrs(layer, tree, ADRS_WOTS_HASH, kp, chain_i, x_start + s, 0)
        v = F(seed, adrs, v)
    return v

def wots_keygen(seed, sk_seed, layer, tree, kp):
    sks = []
    tops = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sks.append(sk_i)
        tops.append(wots_chain(seed, layer, tree, kp, i, 0, W - 1, sk_i))
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return sks, T_l(seed, pk_adrs, tops)

def wots_pk_only(seed, sk_seed, layer, tree, kp):
    """Same as wots_keygen but doesn't return secret keys (saves memory)."""
    tops = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        tops.append(wots_chain(seed, layer, tree, kp, i, 0, W - 1, sk_i))
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return T_l(seed, pk_adrs, tops)

def wots_sign(seed, sks, layer, tree, kp, msg_int):
    digits = wots_digits(msg_int)
    return [wots_chain(seed, layer, tree, kp, i, 0, digits[i], sks[i]) for i in range(L)]

def wots_pk_from_sig(seed, sigma, layer, tree, kp, msg_int):
    digits = wots_digits(msg_int)
    tops = [wots_chain(seed, layer, tree, kp, i, digits[i], W - 1 - digits[i], sigma[i])
            for i in range(L)]
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return T_l(seed, pk_adrs, tops)

# ============================================================
#  XMSS (single layer; treehash without storing the full tree)
# ============================================================

def xmss_root_and_path(seed, sk_seed, layer, tree, leaf_idx, h_param):
    """Streaming TreeHash that yields:
        - the XMSS root
        - the auth path for `leaf_idx` (h_param siblings, leaf→root)
        - the WOTS sks for `leaf_idx`
    Memory: O(h_param) — does NOT materialize the 2^h_param-leaf array.
    """
    n_leaves = 1 << h_param
    auth = [None] * h_param
    sks_at_leaf = [None] * L

    # Stack of (height, node) for incremental Merkle building.
    stack = []

    for kp in range(n_leaves):
        if kp == leaf_idx:
            sks, leaf = wots_keygen(seed, sk_seed, layer, tree, kp)
            sks_at_leaf = sks
        else:
            leaf = wots_pk_only(seed, sk_seed, layer, tree, kp)

        # If this leaf is the *sibling* of leaf_idx at height 0, store it.
        if kp == (leaf_idx ^ 1):
            auth[0] = leaf

        node = leaf
        height = 0
        # Combine with stack top while heights match.
        while stack and stack[-1][0] == height:
            left_h, left_node = stack.pop()
            parent_idx = (kp >> (height + 1))
            adrs = make_adrs(layer, tree, ADRS_XMSS_TREE, 0, 0, height + 1, parent_idx)
            node = H_(seed, adrs, left_node, node)
            height += 1
            # Check if this newly formed node is the auth-path sibling for leaf_idx
            # at level `height`. The sibling of leaf_idx's path at level h is the
            # node whose index equals (leaf_idx >> h) ^ 1.
            sibling_idx_at_h = (leaf_idx >> height) ^ 1
            if parent_idx == sibling_idx_at_h:
                auth[height] = node
        stack.append((height, node))

    # After the full sweep, stack should contain a single node at height h_param.
    assert len(stack) == 1 and stack[0][0] == h_param, \
        f"treehash invariant broken: {[s[0] for s in stack]}"
    root = stack[0][1]
    assert all(a is not None for a in auth), \
        f"missing auth-path entries: {[i for i,a in enumerate(auth) if a is None]}"
    return root, auth, sks_at_leaf

# ============================================================
#  FORS (single 2^a-leaf tree per index)
# ============================================================

def build_fors_subtree(seed, sk_seed, fors_t, ht_tree, ht_leaf, leaf_to_open,
                       a_param):
    """Returns (auth_path[a_param], root, sk_at_leaf_to_open).
    Streaming version: never materializes the full 2^a_param leaf array.
    """
    n_leaves = 1 << a_param
    auth = [None] * a_param
    sk_at_leaf = None
    stack = []   # entries: (height, node)

    for j in range(n_leaves):
        sk = fors_secret(sk_seed, fors_t, j)
        if j == leaf_to_open:
            sk_at_leaf = sk
        adrs = make_adrs(0, ht_tree, ADRS_FORS_TREE, ht_leaf, 0, 0,
                         (fors_t << a_param) | j)
        leaf = F(seed, adrs, sk)
        if j == (leaf_to_open ^ 1):
            auth[0] = leaf
        node = leaf
        height = 0
        while stack and stack[-1][0] == height:
            _, left_node = stack.pop()
            parent_idx = (j >> (height + 1))
            global_y = (fors_t << (a_param - height - 1)) | parent_idx
            adrs = make_adrs(0, ht_tree, ADRS_FORS_TREE, ht_leaf, 0,
                             height + 1, global_y)
            node = H_(seed, adrs, left_node, node)
            height += 1
            sibling_idx_at_h = (leaf_to_open >> height) ^ 1
            if parent_idx == sibling_idx_at_h:
                auth[height] = node
        stack.append((height, node))

    assert len(stack) == 1 and stack[0][0] == a_param
    return auth, stack[0][1], sk_at_leaf

# ============================================================
#  Sign
# ============================================================

def slh_sign(pk_seed, sk_seed, sk_prf, pk_root, message: int, sig_counter: int,
             h_param: int, a_param: int):
    R = derive_R(sk_prf, message, sig_counter)
    digest = h_msg(pk_seed, pk_root, R, message)
    md, leaf_idx = digest_indices(digest, h_param, a_param)
    eprint(f"  digest = {hex(digest)[:18]}…  leaf_idx = {leaf_idx}")

    # FORS
    eprint(f"  FORS ({K} trees of 2^{a_param} leaves)…")
    fors_pieces = []
    fors_roots  = []
    for t in range(K):
        auth, root, sk = build_fors_subtree(pk_seed, sk_seed, t, 0, leaf_idx,
                                            md[t], a_param)
        fors_pieces.append((sk, auth))
        fors_roots.append(root)
        if (t + 1) % 2 == 0:
            eprint(f"    fors {t+1}/{K} done")
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, leaf_idx, 0, 0, 0)
    fors_pk = T_k(pk_seed, roots_adrs, fors_roots)

    # XMSS (single layer, d=1)
    eprint(f"  XMSS layer 0 (2^{h_param} leaves) — building auth path + WOTS sks…")
    xmss_root, xmss_auth, wots_sks = xmss_root_and_path(
        pk_seed, sk_seed, 0, 0, leaf_idx, h_param)
    if xmss_root != pk_root:
        raise AssertionError(f"xmss root mismatch in sign: {hex(xmss_root)} vs {hex(pk_root)}")

    sigma = wots_sign(pk_seed, wots_sks, 0, 0, leaf_idx, fors_pk)

    # Serialize: R(16) | FORS(2400) | WOTS(1088) | XMSS auth(352) = 3856
    out = bytearray()
    out += to_b32(R)[:R_LEN]                        # 16 bytes (high 16B of value word)
    for sk, auth in fors_pieces:                    # 6 × 400
        out += to_b32(sk)[:N]
        for node in auth:
            out += to_b32(node)[:N]
    for chain_v in sigma:                           # 68 × 16
        out += to_b32(chain_v)[:N]
    for node in xmss_auth:                          # 22 × 16
        out += to_b32(node)[:N]
    expected = R_LEN + K * (N + a_param * N) + L * N + h_param * N
    assert len(out) == expected, f"sig len {len(out)} != {expected}"
    return bytes(out)

# ============================================================
#  Local verify mirror (matches the on-chain Yul byte-for-byte)
# ============================================================

def slh_verify(pk_seed, pk_root, message: int, sig: bytes,
               h_param: int, a_param: int) -> bool:
    fors_tree_len = N + a_param * N
    fors_body_len = K * fors_tree_len
    expected = R_LEN + fors_body_len + L * N + h_param * N
    assert len(sig) == expected, f"len {len(sig)} != {expected}"

    R = int.from_bytes(sig[:R_LEN] + b"\x00" * (32 - R_LEN), "big")
    digest = h_msg(pk_seed, pk_root, R, message)
    md, leaf_idx = digest_indices(digest, h_param, a_param)

    # FORS
    fors_off = R_LEN
    roots = []
    for t in range(K):
        sk = int.from_bytes(sig[fors_off:fors_off + N] + b"\x00" * 16, "big")
        auth = [int.from_bytes(
                    sig[fors_off + N + j*N : fors_off + N + (j+1)*N] + b"\x00" * 16,
                    "big")
                for j in range(a_param)]
        fors_off += fors_tree_len

        adrs = make_adrs(0, 0, ADRS_FORS_TREE, leaf_idx, 0, 0,
                         (t << a_param) | md[t])
        node = F(pk_seed, adrs, sk)
        idx = md[t]
        for j in range(a_param):
            sib = auth[j]
            parent_idx = idx >> 1
            global_y = (t << (a_param - j - 1)) | parent_idx
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, leaf_idx, 0, j + 1, global_y)
            node = H_(pk_seed, adrs, node, sib) if (idx & 1) == 0 \
                   else H_(pk_seed, adrs, sib, node)
            idx = parent_idx
        roots.append(node)
    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, leaf_idx, 0, 0, 0)
    current = T_k(pk_seed, roots_adrs, roots)

    # WOTS+
    wots_off = R_LEN + fors_body_len
    sigma = [int.from_bytes(sig[wots_off + i*N : wots_off + (i+1)*N] + b"\x00" * 16, "big")
             for i in range(L)]
    wots_pk = wots_pk_from_sig(pk_seed, sigma, 0, 0, leaf_idx, current)

    # XMSS
    auth_off = wots_off + L * N
    auth = [int.from_bytes(sig[auth_off + j*N : auth_off + (j+1)*N] + b"\x00" * 16, "big")
            for j in range(h_param)]
    node = wots_pk
    m_idx = leaf_idx
    for h in range(h_param):
        sib = auth[h]
        parent_idx = m_idx >> 1
        adrs = make_adrs(0, 0, ADRS_XMSS_TREE, 0, 0, h + 1, parent_idx)
        node = H_(pk_seed, adrs, node, sib) if (m_idx & 1) == 0 \
               else H_(pk_seed, adrs, sib, node)
        m_idx = parent_idx
    return node == pk_root

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
    p = argparse.ArgumentParser()
    p.add_argument("master_sk_hex")
    p.add_argument("message_hex")
    p.add_argument("sig_counter", nargs="?", default=0, type=int)
    p.add_argument("--height", type=int, default=H_DEFAULT,
                   help="override h' for dev (default 22 = NIST). "
                        "Sigs at non-default heights won't verify on-chain.")
    p.add_argument("--a", type=int, default=A,
                   help="override FORS tree height for dev (default 24 = NIST). "
                        "Sigs at non-default a won't verify on-chain.")
    args = p.parse_args()

    master_sk = bytes.fromhex(args.master_sk_hex.replace("0x", ""))
    if len(master_sk) != 32:
        eprint("master_sk must be 32 bytes"); sys.exit(1)
    msg_hex = args.message_hex.replace("0x", "")
    if len(msg_hex) % 2:
        msg_hex = "0" + msg_hex
    message = int(msg_hex, 16) if msg_hex else 0

    h_param = args.height
    a_param = args.a

    t0 = time.time()
    sk_seed, sk_prf, pk_seed = derive_keys(master_sk)
    eprint(f"  pk_seed = {hex(pk_seed)[:18]}…")
    eprint(f"  Building XMSS root (2^{h_param} leaves)… (this is the slow part)")
    pk_root, _, _ = xmss_root_and_path(pk_seed, sk_seed, 0, 0,
                                        leaf_idx=0, h_param=h_param)
    eprint(f"  pk_root = {hex(pk_root)[:18]}…  ({time.time()-t0:.1f}s)")

    eprint(f"  Signing at sig_counter={args.sig_counter}…")
    sig = slh_sign(pk_seed, sk_seed, sk_prf, pk_root, message,
                   args.sig_counter, h_param, a_param)
    assert slh_verify(pk_seed, pk_root, message, sig, h_param, a_param), \
        "local verify failed"
    eprint(f"  Local verify OK.  Sig: {len(sig)} B.  Total: {time.time()-t0:.1f}s")

    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
