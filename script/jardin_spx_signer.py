#!/usr/bin/env python3
"""
JARDÍN SPX signer — plain SPHINCS+ variant (PQ registration path).

Parameters:
    n = 16            keccak256 truncated to 128 bits
    h = 20            total hypertree height
    d = 5             XMSS layers
    h' = h/d = 4      leaves per XMSS tree = 2^4 = 16
    a = 7             FORS tree height (128 leaves/tree)
    k = 20            FORS trees per signature
    w = 8             Winternitz; lg(w) = 3
    l1 = 42           message chains = floor(128/3)
    l2 = 3            checksum chains = ceil(log_w(l1*(w-1)))
    l = 45            total WOTS chains
    R = 32 bytes      per-sig randomness
    ADRS = 12 bytes   compact SPHINCs- convention

Hash primitives (all keccak256, truncated to 16B):
    F(seed, adrs, M16)           = keccak256(seed || adrs || M)[0:16]       44B
    H(seed, adrs, L16 || R16)    = keccak256(seed || adrs || L || R)[0:16]  60B
    T_l(seed, adrs, v[0..l-1])   = keccak256(seed || adrs || v0||..||v44)[0:16]  748B
    T_k(seed, adrs, r[0..k-1])   = keccak256(seed || adrs || r0||..||r19)[0:16]  348B
    Hmsg(R, PKseed, PKroot, M)   = keccak256(R || PKseed || PKroot || M)    32+16+16+|M|B  full 256-bit

Digest parsing (MSB-first, per FIPS-205 base_2b convention):
    md_bits    = D[0   .. 139]     20 chunks of 7 bits → FORS indices
    tree_idx   = D[140 .. 155]     16 bits
    leaf_idx   = D[156 .. 159]      4 bits

ADRS (12-byte, big-endian fields):
    byte  0       layer       uint8
    byte  1..4    tree        uint32
    byte  5       type        uint8  {0=WOTS_HASH, 1=WOTS_PK, 2=XMSS_TREE, 3=FORS_TREE, 4=FORS_ROOTS}
    byte  6..7    keyPair/ci  uint16
    byte  8..9    chainAddr/treeHeight  uint16
    byte 10..11   hashAddr/treeIndex    uint16

Signature layout (6512 bytes):
    0      32     R
    32     2560   FORS (20 trees × (16B sk + 7×16B auth) = 20 × 128B)
    2592   3920   Hypertree (5 layers × (45×16B WOTS + 4×16B XMSS auth) = 5 × 784B)

Usage:
    python3 script/jardin_spx_signer.py <master_sk_hex> <message_hex> [sig_counter]

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) hex on stdout.
"""

import sys, struct, hmac, hashlib, time
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Parameters
# ============================================================

N          = 16
H          = 20
D          = 5
H_PRIME    = 4
A          = 7
K          = 20
W          = 8
LOG_W      = 3
L1         = 42
L2         = 3
L          = 45
R_LEN      = 32

A_MASK       = (1 << A) - 1            # 0x7F
H_PRIME_MASK = (1 << H_PRIME) - 1      # 0xF
TREE_TOP_BITS = H - H_PRIME            # 16
TREE_TOP_MASK = (1 << TREE_TOP_BITS) - 1
W_MASK       = W - 1                   # 7

FORS_TREE_LEN      = N + A * N                      # 16 + 112 = 128
FORS_BODY_LEN      = K * FORS_TREE_LEN              # 20 * 128 = 2560
HT_LAYER_LEN       = L * N + H_PRIME * N            # 720 + 64 = 784
HT_LEN             = D * HT_LAYER_LEN               # 5 * 784 = 3920
SIG_LEN            = R_LEN + FORS_BODY_LEN + HT_LEN # 32 + 2560 + 3920 = 6512

# ADRS types
ADRS_WOTS_HASH  = 0
ADRS_WOTS_PK    = 1
ADRS_XMSS_TREE  = 2
ADRS_FORS_TREE  = 3
ADRS_FORS_ROOTS = 4

# ============================================================
#  Hash primitives
# ============================================================

def keccak256(data: bytes) -> bytes:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()

def to16(v: int) -> bytes:
    return (v & ((1 << 128) - 1)).to_bytes(16, "big")

def to32(v: int) -> bytes:
    return v.to_bytes(32, "big")

def pack_adrs(layer=0, tree=0, atype=0, kp=0, chainAddr=0, hashAddr=0) -> bytes:
    return (
        (layer     & 0xFF)       .to_bytes(1, "big") +
        (tree      & 0xFFFFFFFF) .to_bytes(4, "big") +
        (atype     & 0xFF)       .to_bytes(1, "big") +
        (kp        & 0xFFFF)     .to_bytes(2, "big") +
        (chainAddr & 0xFFFF)     .to_bytes(2, "big") +
        (hashAddr  & 0xFFFF)     .to_bytes(2, "big")
    )
assert len(pack_adrs()) == 12

def F(seed16: bytes, adrs12: bytes, M16: bytes) -> bytes:
    """F(seed, adrs, M) = keccak(seed || adrs || M)[0:16], 44B input."""
    return keccak256(seed16 + adrs12 + M16)[:N]

def H(seed16: bytes, adrs12: bytes, L16: bytes, R16: bytes) -> bytes:
    """H(seed, adrs, L || R) = keccak(seed || adrs || L || R)[0:16], 60B input."""
    return keccak256(seed16 + adrs12 + L16 + R16)[:N]

def T_l(seed16: bytes, adrs12: bytes, vs: list) -> bytes:
    """T_l(seed, adrs, v0..v44) for WOTS PK compression, 748B input."""
    return keccak256(seed16 + adrs12 + b"".join(vs))[:N]

def T_k(seed16: bytes, adrs12: bytes, rs: list) -> bytes:
    """T_k(seed, adrs, r0..r19) for FORS root compression, 348B input."""
    return keccak256(seed16 + adrs12 + b"".join(rs))[:N]

def h_msg(R32: bytes, pkSeed16: bytes, pkRoot16: bytes, M: bytes) -> bytes:
    """Hmsg = keccak(R || PKseed || PKroot || M), full 32B output."""
    return keccak256(R32 + pkSeed16 + pkRoot16 + M)

# ============================================================
#  Digest parsing (MSB-first)
# ============================================================

def digest_indices(D_bytes: bytes):
    """Parse 32-byte digest: k=20 7-bit FORS leaves, 16-bit tree_idx, 4-bit leaf_idx.
    MSB-first bit stream (FIPS-205 convention)."""
    d_int = int.from_bytes(D_bytes, "big")
    md = []
    for i in range(K):
        # bits MSB i*7 .. i*7+6 = LSB (255 - i*7) .. (249 - i*7)
        shift = 256 - 7 * (i + 1)   # = 249 - i*7
        md.append((d_int >> shift) & A_MASK)
    tree_idx = (d_int >> (256 - 140 - 16)) & TREE_TOP_MASK  # D[140..155]
    leaf_idx = (d_int >> (256 - 140 - 16 - H_PRIME)) & H_PRIME_MASK  # D[156..159]
    return md, tree_idx, leaf_idx

# ============================================================
#  base_w + WOTS+ checksum
# ============================================================

def base_w_node(node16: bytes):
    """Extract l1=42 base-8 digits from 128-bit node, MSB-first. 126 bits used, 2 trailing bits ignored."""
    n_int = int.from_bytes(node16, "big")  # 128-bit
    digits = []
    for i in range(L1):
        # bits MSB i*3 .. i*3+2 of a 128-bit value
        shift = 128 - 3 * (i + 1)  # = 125 - i*3
        digits.append((n_int >> shift) & W_MASK)
    return digits

def wots_checksum(msg_digits):
    """WOTS+ checksum: csum = sum(w-1 - m_i) for i=0..l1-1.
    Encode in base-w as l2=3 digits, MSB-first, after left-shifting by 7 bits
    to byte-align (SLH-DSA convention)."""
    assert len(msg_digits) == L1
    csum = sum((W - 1) - d for d in msg_digits)  # 0..42*7 = 0..294
    # shift left by (8*ceil(l2*lg(w)/8) - l2*lg(w)) = 8*2 - 9 = 7 bits
    csum_shifted = csum << 7
    # Encode as 2 bytes, then base_w extract 3 digits
    cb = csum_shifted.to_bytes(2, "big")
    cb_int = int.from_bytes(cb, "big")  # 16-bit
    out = []
    for i in range(L2):
        shift = 16 - 3 * (i + 1)  # = 13 - i*3
        out.append((cb_int >> shift) & W_MASK)
    return out

def wots_digits(node16: bytes):
    """Return l=45 base-w digits for WOTS+ signing/verification."""
    md = base_w_node(node16)
    cs = wots_checksum(md)
    return md + cs

# ============================================================
#  Key derivation (BIP-39-ish master -> SPX keys)
# ============================================================

def hmac512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()

def derive_spx_keys(master_sk: bytes):
    sk_seed = hmac512(master_sk, b"JARDIN/SPX/SKSEED")[:N]
    sk_prf  = hmac512(master_sk, b"JARDIN/SPX/SKPRF" )[:N]
    pk_seed = hmac512(master_sk, b"JARDIN/SPX/PKSEED")[:N]
    return sk_seed, sk_prf, pk_seed

def wots_secret(sk_seed: bytes, layer: int, tree: int, kp: int, chain_idx: int) -> bytes:
    data = sk_seed + b"spx_wots" + struct.pack(">I", layer) + tree.to_bytes(8, "big") + \
           struct.pack(">I", kp) + struct.pack(">I", chain_idx)
    return keccak256(data)[:N]

def fors_secret(sk_seed: bytes, tree_idx: int, leaf_idx: int) -> bytes:
    data = sk_seed + b"spx_fors" + struct.pack(">I", tree_idx) + struct.pack(">I", leaf_idx)
    return keccak256(data)[:N]

# ============================================================
#  WOTS+ (plain, with checksum)
# ============================================================

def chain(seed16, layer, tree, kp, chain_i, x_start, steps, val):
    """Walk a WOTS+ chain: val <- F(seed, adrs, val) for s = x_start..x_start+steps-1."""
    v = val
    for s in range(steps):
        adrs = pack_adrs(layer=layer, tree=tree, atype=ADRS_WOTS_HASH,
                         kp=kp, chainAddr=chain_i, hashAddr=x_start + s)
        v = F(seed16, adrs, v)
    return v

def wots_pk_gen(seed16, sk_seed, layer, tree, kp):
    """Return (sks[L], wots_pk)."""
    sks = []
    tops = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sks.append(sk_i)
        tops.append(chain(seed16, layer, tree, kp, i, 0, W - 1, sk_i))
    pk_adrs = pack_adrs(layer=layer, tree=tree, atype=ADRS_WOTS_PK, kp=kp)
    return sks, T_l(seed16, pk_adrs, tops)

def wots_sign(seed16, sks, layer, tree, kp, msg16):
    digits = wots_digits(msg16)
    sigma = []
    for i in range(L):
        sigma.append(chain(seed16, layer, tree, kp, i, 0, digits[i], sks[i]))
    return sigma, digits

def wots_pk_from_sig(seed16, sigma, layer, tree, kp, msg16):
    digits = wots_digits(msg16)
    tops = []
    for i in range(L):
        tops.append(chain(seed16, layer, tree, kp, i, digits[i], W - 1 - digits[i], sigma[i]))
    pk_adrs = pack_adrs(layer=layer, tree=tree, atype=ADRS_WOTS_PK, kp=kp)
    return T_l(seed16, pk_adrs, tops)

# ============================================================
#  XMSS per layer (h' = 4)
# ============================================================

def build_xmss_tree(seed16, sk_seed, layer, tree):
    n_leaves = 1 << H_PRIME
    wots_sks = []
    leaves = []
    for kp in range(n_leaves):
        sks, pk = wots_pk_gen(seed16, sk_seed, layer, tree, kp)
        wots_sks.append(sks)
        leaves.append(pk)
    nodes = [leaves]
    for h in range(H_PRIME):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            adrs = pack_adrs(layer=layer, tree=tree, atype=ADRS_XMSS_TREE,
                             chainAddr=h + 1, hashAddr=parent_idx)
            level.append(H(seed16, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return wots_sks, nodes, nodes[H_PRIME][0]

def xmss_auth_path(nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(nodes[h][idx ^ 1])
        idx >>= 1
    return path

# ============================================================
#  FORS
# ============================================================

def fors_build_subtree(seed16, sk_seed, tree_idx, ht_tree_idx, ht_leaf_idx):
    """Build FORS subtree with full leaf hashes under a given (ht_tree_idx, ht_leaf_idx)."""
    n_leaves = 1 << A
    leaves = []
    for j in range(n_leaves):
        sk = fors_secret(sk_seed, tree_idx, j)
        tree_leaf_global = tree_idx * n_leaves + j
        adrs = pack_adrs(layer=0, tree=ht_tree_idx, atype=ADRS_FORS_TREE,
                         kp=ht_leaf_idx, chainAddr=0, hashAddr=tree_leaf_global)
        leaves.append(F(seed16, adrs, sk))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            # treeIndex for parent at level h+1 = tree_idx * 2^(A-h-1) + parent_idx
            # (= leftmost_global_leaf >> (h+1); same for all leaves under this parent)
            tree_index_field = tree_idx * (1 << (A - h - 1)) + parent_idx
            adrs = pack_adrs(layer=0, tree=ht_tree_idx, atype=ADRS_FORS_TREE,
                             kp=ht_leaf_idx, chainAddr=h + 1, hashAddr=tree_index_field)
            level.append(H(seed16, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[A][0]

# ============================================================
#  Top-layer PK root (keygen)
# ============================================================

def build_pk_root(seed16, sk_seed):
    _, _, root = build_xmss_tree(seed16, sk_seed, D - 1, 0)
    return root

# ============================================================
#  Signing
# ============================================================

def derive_R(sk_prf: bytes, message: bytes, sig_counter: int) -> bytes:
    return keccak256(sk_prf + b"spx_R" + message + struct.pack(">I", sig_counter))[:R_LEN]

def spx_sign(pk_seed, sk_seed, sk_prf, pk_root, message: bytes, sig_counter: int = 0):
    R = derive_R(sk_prf, message, sig_counter)
    digest = h_msg(R, pk_seed, pk_root, message)
    md, tree_idx, leaf_idx = digest_indices(digest)

    eprint(f"  digest[0..4] = {digest[:4].hex()}, tree_idx = {tree_idx}, leaf_idx = {leaf_idx}")

    # --- FORS ---
    eprint("  Signing FORS...")
    fors_pieces = []  # per-tree (secret_16B, auth_paths_list_of_16B)
    roots = []
    for t in range(K):
        nodes, root = fors_build_subtree(pk_seed, sk_seed, t, tree_idx, leaf_idx)
        sk = fors_secret(sk_seed, t, md[t])
        # auth path of the leaf at md[t]
        path = []
        idx = md[t]
        for h in range(A):
            path.append(nodes[h][idx ^ 1])
            idx >>= 1
        fors_pieces.append((sk, path))
        roots.append(root)
    roots_adrs = pack_adrs(layer=0, tree=tree_idx, atype=ADRS_FORS_ROOTS, kp=leaf_idx)
    fors_pk = T_k(pk_seed, roots_adrs, roots)

    # --- Hypertree ---
    eprint("  Signing hypertree...")
    current = fors_pk
    cur_tree = tree_idx
    cur_leaf = leaf_idx
    ht_layers = []
    for layer in range(D):
        eprint(f"    Layer {layer}: tree={cur_tree}, leaf={cur_leaf}")
        wots_sks, tree_nodes, _ = build_xmss_tree(pk_seed, sk_seed, layer, cur_tree)
        sigma, _ = wots_sign(pk_seed, wots_sks[cur_leaf], layer, cur_tree, cur_leaf, current)
        auth = xmss_auth_path(tree_nodes, cur_leaf, H_PRIME)
        ht_layers.append((sigma, auth))

        # climb to next layer input
        wots_pk = wots_pk_from_sig(pk_seed, sigma, layer, cur_tree, cur_leaf, current)
        node = wots_pk
        m_idx = cur_leaf
        for h in range(H_PRIME):
            sib = auth[h]
            parent_idx = m_idx >> 1
            adrs = pack_adrs(layer=layer, tree=cur_tree, atype=ADRS_XMSS_TREE,
                             chainAddr=h + 1, hashAddr=parent_idx)
            if m_idx & 1 == 0:
                node = H(pk_seed, adrs, node, sib)
            else:
                node = H(pk_seed, adrs, sib, node)
            m_idx = parent_idx
        current = node

        # advance: leaf_idx = tree & 0xF, tree = tree >> h'
        cur_leaf = cur_tree & H_PRIME_MASK
        cur_tree = cur_tree >> H_PRIME

    if current != pk_root:
        raise AssertionError(f"sign: root mismatch: {current.hex()} vs {pk_root.hex()}")

    # --- Serialize ---
    out = bytearray()
    out += R
    for sk, path in fors_pieces:
        out += sk
        for node in path:
            out += node
    for sigma, auth in ht_layers:
        for chain_v in sigma:
            out += chain_v
        for node in auth:
            out += node
    assert len(out) == SIG_LEN, f"sig len {len(out)} != {SIG_LEN}"
    return bytes(out)

# ============================================================
#  Local verifier (mirrors planned Yul byte-for-byte)
# ============================================================

def spx_verify(pk_seed, pk_root, message: bytes, sig: bytes) -> bool:
    if len(sig) != SIG_LEN:
        raise AssertionError(f"len {len(sig)} != {SIG_LEN}")
    R = sig[0:32]
    digest = h_msg(R, pk_seed, pk_root, message)
    md, tree_idx, leaf_idx = digest_indices(digest)

    # FORS
    fors_off = R_LEN
    roots = []
    for t in range(K):
        sk = sig[fors_off : fors_off + N]
        auth = [sig[fors_off + N + j * N : fors_off + N + (j + 1) * N] for j in range(A)]
        fors_off += FORS_TREE_LEN

        tree_leaf_global = t * (1 << A) + md[t]
        adrs = pack_adrs(layer=0, tree=tree_idx, atype=ADRS_FORS_TREE,
                         kp=leaf_idx, chainAddr=0, hashAddr=tree_leaf_global)
        node = F(pk_seed, adrs, sk)

        idx = md[t]
        for j in range(A):
            sib = auth[j]
            parent_idx = idx >> 1
            adrs = pack_adrs(layer=0, tree=tree_idx, atype=ADRS_FORS_TREE,
                             kp=leaf_idx, chainAddr=j + 1,
                             hashAddr=tree_leaf_global >> (j + 1))
            if idx & 1 == 0:
                node = H(pk_seed, adrs, node, sib)
            else:
                node = H(pk_seed, adrs, sib, node)
            idx = parent_idx
        roots.append(node)
    roots_adrs = pack_adrs(layer=0, tree=tree_idx, atype=ADRS_FORS_ROOTS, kp=leaf_idx)
    fors_pk = T_k(pk_seed, roots_adrs, roots)

    # Hypertree
    ht_off = R_LEN + FORS_BODY_LEN
    current = fors_pk
    cur_tree = tree_idx
    cur_leaf = leaf_idx
    for layer in range(D):
        base = ht_off + layer * HT_LAYER_LEN
        sigma = [sig[base + i * N : base + (i + 1) * N] for i in range(L)]
        auth  = [sig[base + L * N + j * N : base + L * N + (j + 1) * N] for j in range(H_PRIME)]

        wots_pk = wots_pk_from_sig(pk_seed, sigma, layer, cur_tree, cur_leaf, current)

        node = wots_pk
        m_idx = cur_leaf
        for h in range(H_PRIME):
            sib = auth[h]
            parent_idx = m_idx >> 1
            adrs = pack_adrs(layer=layer, tree=cur_tree, atype=ADRS_XMSS_TREE,
                             chainAddr=h + 1, hashAddr=parent_idx)
            if m_idx & 1 == 0:
                node = H(pk_seed, adrs, node, sib)
            else:
                node = H(pk_seed, adrs, sib, node)
            m_idx = parent_idx
        current = node

        cur_leaf = cur_tree & H_PRIME_MASK
        cur_tree = cur_tree >> H_PRIME

    return current == pk_root

# ============================================================
#  CLI
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def abi_encode(seed16, root16, sig: bytes) -> bytes:
    # seed and root come in as 16B; ABI-encode as bytes32 with value in high 16 bytes
    seed_b32 = seed16 + b"\x00" * 16
    root_b32 = root16 + b"\x00" * 16
    enc = seed_b32 + root_b32 + (0x60).to_bytes(32, "big") + len(sig).to_bytes(32, "big")
    enc += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return enc

def main():
    if len(sys.argv) < 3:
        eprint("Usage: python3 jardin_spx_signer.py <master_sk_hex> <message_hex> [sig_counter]")
        sys.exit(1)
    master_sk = bytes.fromhex(sys.argv[1].replace("0x", ""))
    if len(master_sk) != 32:
        eprint("master_sk must be 32 bytes"); sys.exit(1)
    message_hex = sys.argv[2].replace("0x", "")
    if len(message_hex) % 2:
        message_hex = "0" + message_hex
    message = bytes.fromhex(message_hex)
    # pad / truncate message to 32 bytes for consistency with our tests (bytes32 hash)
    if len(message) < 32:
        message = message.rjust(32, b"\x00")
    sig_counter = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    t0 = time.time()
    sk_seed, sk_prf, pk_seed = derive_spx_keys(master_sk)
    eprint(f"  pk_seed = {pk_seed.hex()}")
    eprint(f"  Building top-layer XMSS (layer={D-1}, {1 << H_PRIME} WOTS keypairs)...")
    pk_root = build_pk_root(pk_seed, sk_seed)
    eprint(f"  pk_root = {pk_root.hex()}")

    eprint(f"  Signing at sig_counter={sig_counter}...")
    sig = spx_sign(pk_seed, sk_seed, sk_prf, pk_root, message, sig_counter)
    assert spx_verify(pk_seed, pk_root, message, sig), "local verify failed"
    eprint(f"  Local verify OK. Sig: {len(sig)} bytes. Total: {time.time() - t0:.1f}s")

    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
