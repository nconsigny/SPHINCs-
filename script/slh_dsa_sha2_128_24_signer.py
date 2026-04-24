#!/usr/bin/env python3
"""
SLH-DSA-SHA2-128-24 signer — bit-exact NIST FIPS 205 / SP 800-230 compliance.

Implements the SLH-DSA-SHA2-128-24 parameter set exactly as NIST specifies it
(so a signature produced here validates against any conforming verifier,
including our on-chain src/SLH-DSA-SHA2-128-24verifier.sol which uses the
SHA-256 precompile).

Parameters (FIPS 205 §11, SP 800-230 Table 1):
    n  = 16     h  = 22    d  = 1    h' = 22
    a  = 24     k  = 6     w  = 4 (lgw=2)     m  = 21
    l1 = 64, l2 = 4, l = 68

Hash primitives (FIPS 205 §11.2.1, n=16 instance — SHA-256 throughout):
    F(PK.seed, ADRS, M1) = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M1)[0..n-1]
    H(PK.seed, ADRS, M2) = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M2)[0..n-1]
    T_l(PK.seed, ADRS, M)= SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ M)[0..n-1]
    PRF(PK.seed, SK.seed, ADRS)
                         = SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRSc ‖ SK.seed)[0..n-1]
    PRFmsg(SK.prf, opt_rand, M)
                         = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand ‖ M))
    Hmsg(R, PK.seed, PK.root, M)
                         = MGF1-SHA-256(R ‖ PK.seed ‖ PK.root ‖ M, m)

ADRSc (compressed 22-byte addressing, FIPS 205 §11.2):
    layer(1) ‖ tree(8) ‖ type(1) ‖ 12 type-dependent bytes

Signature layout (3,856 B):
    R(16) | FORS = 6 × (sk 16 + auth 24·16) = 2,400
          | HT   = 1 × (WOTS 68·16 + auth 22·16) = 1,440

NOTE:  d=1, h=22 means the public key is the root of a 2^22-leaf XMSS tree.
       Building it takes on the order of ~hours in Python (~800M SHA-256
       calls for the full hypertree keygen).  For dev iteration the CLI
       accepts --height and --a overrides; non-default values still produce
       self-consistent signatures but will not verify against the on-chain
       contract, which hardcodes h=22 a=24.

Usage:
    python3 script/slh_dsa_sha2_128_24_signer.py <master_sk_hex> <message_hex> \\
        [sig_counter] [--height N] [--a N]
"""

import sys, os, time, hmac, hashlib, struct, argparse

# ============================================================
#  Parameters
# ============================================================

N          = 16
H_DEFAULT  = 22
D          = 1
A_DEFAULT  = 24
K          = 6
W          = 4
LOG_W      = 2
L1         = 64
L2         = 4
L          = 68
M_LEN      = 21          # Hmsg output bytes (FIPS 205 m parameter)
R_LEN      = N           # 16 bytes on wire

# ADRS types
ADRS_WOTS_HASH  = 0
ADRS_WOTS_PK    = 1
ADRS_TREE       = 2
ADRS_FORS_TREE  = 3
ADRS_FORS_ROOTS = 4
ADRS_WOTS_PRF   = 5
ADRS_FORS_PRF   = 6

# ============================================================
#  SHA-256 helpers
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def mgf1_sha256(seed: bytes, length: int) -> bytes:
    """MGF1-SHA-256 per RFC 2437 / PKCS#1."""
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + struct.pack(">I", counter))
        counter += 1
    return out[:length]

# ============================================================
#  ADRSc encoding (FIPS 205 §11.2, 22-byte compressed ADRS)
# ============================================================

def adrsc(layer: int, tree: int, atype: int,
          kp: int = 0, chain: int = 0, height: int = 0,
          tree_index: int = 0) -> bytes:
    """Build a 22-byte compressed ADRS.  `chain` doubles as `height` for
    TREE/FORS_TREE types; callers use the canonical naming below."""
    # layer(1) ‖ tree(8) ‖ type(1) ‖ <12-byte type-dependent field>
    out = bytes([layer & 0xFF]) + (tree & ((1<<64)-1)).to_bytes(8, "big") \
        + bytes([atype & 0xFF])
    if atype == ADRS_WOTS_HASH:
        out += struct.pack(">III", kp, chain, height)
    elif atype == ADRS_WOTS_PK:
        out += struct.pack(">I", kp) + b"\x00" * 8
    elif atype == ADRS_TREE:
        out += b"\x00" * 4 + struct.pack(">II", height, tree_index)
    elif atype == ADRS_FORS_TREE:
        out += struct.pack(">III", kp, height, tree_index)
    elif atype == ADRS_FORS_ROOTS:
        out += struct.pack(">I", kp) + b"\x00" * 8
    elif atype == ADRS_WOTS_PRF:
        out += struct.pack(">II", kp, chain) + b"\x00" * 4
    elif atype == ADRS_FORS_PRF:
        out += struct.pack(">I", kp) + b"\x00" * 4 + struct.pack(">I", tree_index)
    else:
        raise ValueError(f"unknown ADRS type {atype}")
    assert len(out) == 22, f"adrsc len {len(out)} != 22"
    return out

# ============================================================
#  Hash primitives (all SHA-256, PK.seed padded to one block)
# ============================================================

_PAD48 = b"\x00" * (64 - N)   # padding such that PK.seed ‖ pad spans one SHA block

def F(pk_seed: bytes, adrs: bytes, M1: bytes) -> bytes:
    return sha256(pk_seed + _PAD48 + adrs + M1)[:N]

def H_(pk_seed: bytes, adrs: bytes, M2: bytes) -> bytes:
    return sha256(pk_seed + _PAD48 + adrs + M2)[:N]

def T_l(pk_seed: bytes, adrs: bytes, M: bytes) -> bytes:
    return sha256(pk_seed + _PAD48 + adrs + M)[:N]

def PRF(pk_seed: bytes, sk_seed: bytes, adrs: bytes) -> bytes:
    return sha256(pk_seed + _PAD48 + adrs + sk_seed)[:N]

def PRFmsg(sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
    return hmac_sha256(sk_prf, opt_rand + M)[:N]

def Hmsg(R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
    # FIPS 205 §10.2 (SHA-2 instantiation, category 1, n=16):
    #   Hmsg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    inner = sha256(R + pk_seed + pk_root + M)
    return mgf1_sha256(R + pk_seed + inner, M_LEN)

# ============================================================
#  FIPS 205 base_2^b (MSB-first)
# ============================================================

def base_2b(X: bytes, b: int, out_len: int):
    """Algorithm 4:  read `out_len` unsigned b-bit integers from X, MSB-first."""
    result = [0] * out_len
    inp = 0           # next byte to consume
    total = 0         # bit buffer
    bits = 0
    for o in range(out_len):
        while bits < b:
            total = (total << 8) | X[inp]
            inp += 1
            bits += 8
        bits -= b
        result[o] = (total >> bits) & ((1 << b) - 1)
    return result

def digest_indices(digest: bytes, h_param: int, a_param: int):
    """Parse the m-byte digest into (md[0..k-1], leafIdx).

    Matches the sphincs/sphincsplus reference (= PQClean) convention, which
    is the industry-standard SLH-DSA behaviour: LSB-first bit extraction
    within each byte for FORS indices, then a big-endian read of the next
    few bytes masked to `h_param` low bits for the leaf index.

    (This differs from a naïve MSB-first `base_2^b` read: for a=24 the
    FORS index is effectively a LITTLE-ENDIAN 3-byte read of
    `digest[3t..3t+3]`.)
    """
    fors_bits   = K * a_param
    fors_bytes  = (fors_bits + 7) // 8
    leaf_bytes  = (h_param + 7) // 8
    assert M_LEN == fors_bytes + leaf_bytes, \
        f"m mismatch for h={h_param} a={a_param}: {fors_bytes}+{leaf_bytes} != {M_LEN}"

    md = []
    offset = 0
    for _t in range(K):
        idx = 0
        for j in range(a_param):
            idx |= ((digest[offset >> 3] >> (offset & 7)) & 1) << j
            offset += 1
        md.append(idx)

    leaf_val = int.from_bytes(digest[fors_bytes:fors_bytes + leaf_bytes], "big")
    leaf_idx = leaf_val & ((1 << h_param) - 1)
    return md, leaf_idx

# ============================================================
#  WOTS+ digit parsing (plain SLH-DSA, MSB-first base_w=4)
# ============================================================

def wots_msg_digits(M: bytes):
    return base_2b(M, LOG_W, L1)

def wots_checksum(msg_digits):
    csum = sum((W - 1) - d for d in msg_digits)
    # l2·lgw = 8 bits ⇒ byte-aligned, no pre-shift.
    csum_bytes = (L2 * LOG_W + 7) // 8
    csum_bytestr = csum.to_bytes(csum_bytes, "big")
    return base_2b(csum_bytestr, LOG_W, L2)

def wots_digits(M: bytes):
    md = wots_msg_digits(M)
    return md + wots_checksum(md)

# ============================================================
#  Key derivation (BIP-39-ish — JARDIN convention, distinct from NIST)
# ============================================================

def hmac512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()

def derive_keys(master_sk: bytes):
    """Returns (sk_seed, sk_prf, pk_seed) as raw N-byte strings."""
    sk_seed = hmac512(master_sk, b"JARDIN/SLH2128_24/SKSEED")[:N]
    sk_prf  = hmac512(master_sk, b"JARDIN/SLH2128_24/SKPRF" )[:N]
    pk_seed = hmac512(master_sk, b"JARDIN/SLH2128_24/PKSEED")[:N]
    return sk_seed, sk_prf, pk_seed

# ============================================================
#  WOTS+  (single-layer XMSS helper)
# ============================================================

def wots_secret(pk_seed, sk_seed, layer, tree, kp, chain_i):
    """PRF-derived WOTS secret key byte-string."""
    return PRF(pk_seed, sk_seed,
               adrsc(layer, tree, ADRS_WOTS_PRF, kp=kp, chain=chain_i))

def wots_chain(pk_seed, layer, tree, kp, chain_i, start, steps, val):
    v = val
    for s in range(steps):
        v = F(pk_seed,
              adrsc(layer, tree, ADRS_WOTS_HASH,
                    kp=kp, chain=chain_i, height=start + s),
              v)
    return v

def wots_keygen(pk_seed, sk_seed, layer, tree, kp):
    sks, tops = [], []
    for i in range(L):
        sk_i = wots_secret(pk_seed, sk_seed, layer, tree, kp, i)
        sks.append(sk_i)
        tops.append(wots_chain(pk_seed, layer, tree, kp, i, 0, W - 1, sk_i))
    return sks, T_l(pk_seed, adrsc(layer, tree, ADRS_WOTS_PK, kp=kp), b"".join(tops))

def wots_pk_only(pk_seed, sk_seed, layer, tree, kp):
    tops = []
    for i in range(L):
        sk_i = wots_secret(pk_seed, sk_seed, layer, tree, kp, i)
        tops.append(wots_chain(pk_seed, layer, tree, kp, i, 0, W - 1, sk_i))
    return T_l(pk_seed, adrsc(layer, tree, ADRS_WOTS_PK, kp=kp), b"".join(tops))

def wots_sign(pk_seed, sks, layer, tree, kp, msg_bytes):
    digits = wots_digits(msg_bytes)
    return [wots_chain(pk_seed, layer, tree, kp, i, 0, digits[i], sks[i])
            for i in range(L)]

def wots_pk_from_sig(pk_seed, sigma, layer, tree, kp, msg_bytes):
    digits = wots_digits(msg_bytes)
    tops = [wots_chain(pk_seed, layer, tree, kp, i, digits[i],
                       W - 1 - digits[i], sigma[i])
            for i in range(L)]
    return T_l(pk_seed, adrsc(layer, tree, ADRS_WOTS_PK, kp=kp), b"".join(tops))

# ============================================================
#  XMSS (streaming TreeHash — O(h) memory)
# ============================================================

def xmss_root_and_path(pk_seed, sk_seed, layer, tree, leaf_idx, h_param):
    n_leaves = 1 << h_param
    auth = [None] * h_param
    sks_at_leaf = None
    stack = []
    for kp in range(n_leaves):
        if kp == leaf_idx:
            sks, leaf = wots_keygen(pk_seed, sk_seed, layer, tree, kp)
            sks_at_leaf = sks
        else:
            leaf = wots_pk_only(pk_seed, sk_seed, layer, tree, kp)
        if kp == (leaf_idx ^ 1):
            auth[0] = leaf
        node = leaf
        height = 0
        while stack and stack[-1][0] == height:
            _, left = stack.pop()
            parent_idx = kp >> (height + 1)
            adr = adrsc(layer, tree, ADRS_TREE,
                        height=height + 1, tree_index=parent_idx)
            node = H_(pk_seed, adr, left + node)
            height += 1
            if parent_idx == (leaf_idx >> height) ^ 1:
                auth[height] = node
        stack.append((height, node))
    assert len(stack) == 1 and stack[0][0] == h_param
    return stack[0][1], auth, sks_at_leaf

# ============================================================
#  FORS
# ============================================================

def fors_secret(pk_seed, sk_seed, kp, fors_t, leaf_in_tree, a_param):
    """FORS secret key.  FIPS 205 uses FORS_PRF with tree_index = (t<<a) | leaf."""
    return PRF(pk_seed, sk_seed,
               adrsc(0, 0, ADRS_FORS_PRF, kp=kp,
                     tree_index=(fors_t << a_param) | leaf_in_tree))

def build_fors_subtree(pk_seed, sk_seed, kp, fors_t, leaf_to_open, a_param):
    """Streaming version: returns (auth[a], root, sk_at_leaf_to_open)."""
    n_leaves = 1 << a_param
    auth = [None] * a_param
    sk_at_leaf = None
    stack = []
    for j in range(n_leaves):
        sk = fors_secret(pk_seed, sk_seed, kp, fors_t, j, a_param)
        if j == leaf_to_open:
            sk_at_leaf = sk
        adr = adrsc(0, 0, ADRS_FORS_TREE, kp=kp,
                    height=0, tree_index=(fors_t << a_param) | j)
        leaf = F(pk_seed, adr, sk)
        if j == (leaf_to_open ^ 1):
            auth[0] = leaf
        node = leaf
        height = 0
        while stack and stack[-1][0] == height:
            _, left = stack.pop()
            parent_idx = j >> (height + 1)
            global_y = (fors_t << (a_param - height - 1)) | parent_idx
            adr = adrsc(0, 0, ADRS_FORS_TREE, kp=kp,
                        height=height + 1, tree_index=global_y)
            node = H_(pk_seed, adr, left + node)
            height += 1
            if parent_idx == (leaf_to_open >> height) ^ 1:
                auth[height] = node
        stack.append((height, node))
    assert len(stack) == 1 and stack[0][0] == a_param
    return auth, stack[0][1], sk_at_leaf

# ============================================================
#  Sign / Verify
# ============================================================

def slh_sign(pk_seed, sk_seed, sk_prf, pk_root, message: bytes,
             sig_counter: int, h_param: int, a_param: int):
    # Deterministic randomizer (NIST allows deterministic variant):
    #   R = PRFmsg(SK.prf, opt_rand = 0..0, M)  — opt_rand from counter
    opt_rand = struct.pack(">I", sig_counter) + b"\x00" * (N - 4)
    R = PRFmsg(sk_prf, opt_rand, message)
    digest = Hmsg(R, pk_seed, pk_root, message)
    md, leaf_idx = digest_indices(digest, h_param, a_param)
    eprint(f"  digest = 0x{digest.hex()[:16]}…  leaf_idx = {leaf_idx}")

    # FORS
    eprint(f"  FORS ({K} trees of 2^{a_param} leaves)…")
    fors_pieces = []
    fors_roots  = []
    for t in range(K):
        auth, r, sk = build_fors_subtree(pk_seed, sk_seed, leaf_idx, t,
                                          md[t], a_param)
        fors_pieces.append((sk, auth))
        fors_roots.append(r)
        if (t + 1) % 2 == 0:
            eprint(f"    fors {t+1}/{K} done")
    fors_pk = T_l(pk_seed,
                  adrsc(0, 0, ADRS_FORS_ROOTS, kp=leaf_idx),
                  b"".join(fors_roots))

    # XMSS (single layer)
    eprint(f"  XMSS layer 0 (2^{h_param} leaves)…")
    xmss_root, xmss_auth, wots_sks = xmss_root_and_path(
        pk_seed, sk_seed, 0, 0, leaf_idx, h_param)
    if xmss_root != pk_root:
        raise AssertionError(
            f"sign: xmss root mismatch {xmss_root.hex()} vs {pk_root.hex()}")

    sigma = wots_sign(pk_seed, wots_sks, 0, 0, leaf_idx, fors_pk)

    out = bytearray()
    out += R                                                  # 16
    for sk, auth in fors_pieces:
        out += sk
        for node in auth:
            out += node
    for s in sigma:
        out += s
    for node in xmss_auth:
        out += node
    expected = R_LEN + K * (N + a_param * N) + L * N + h_param * N
    assert len(out) == expected
    return bytes(out)

def slh_verify(pk_seed, pk_root, message: bytes, sig: bytes,
               h_param: int, a_param: int) -> bool:
    fors_tree_len = N + a_param * N
    fors_body_len = K * fors_tree_len
    expected = R_LEN + fors_body_len + L * N + h_param * N
    if len(sig) != expected:
        return False

    R = sig[:R_LEN]
    digest = Hmsg(R, pk_seed, pk_root, message)
    md, leaf_idx = digest_indices(digest, h_param, a_param)

    # FORS
    off = R_LEN
    roots = []
    for t in range(K):
        sk = sig[off:off + N]
        auth = [sig[off + N + j*N : off + N + (j+1)*N] for j in range(a_param)]
        off += fors_tree_len

        node = F(pk_seed, adrsc(0, 0, ADRS_FORS_TREE, kp=leaf_idx,
                                height=0, tree_index=(t << a_param) | md[t]), sk)
        idx = md[t]
        for j in range(a_param):
            sib = auth[j]
            parent_idx = idx >> 1
            global_y = (t << (a_param - j - 1)) | parent_idx
            adr = adrsc(0, 0, ADRS_FORS_TREE, kp=leaf_idx,
                        height=j + 1, tree_index=global_y)
            node = H_(pk_seed, adr, node + sib) if (idx & 1) == 0 \
                   else H_(pk_seed, adr, sib + node)
            idx = parent_idx
        roots.append(node)
    current = T_l(pk_seed,
                  adrsc(0, 0, ADRS_FORS_ROOTS, kp=leaf_idx),
                  b"".join(roots))

    # WOTS+
    wots_off = R_LEN + fors_body_len
    sigma = [sig[wots_off + i*N : wots_off + (i+1)*N] for i in range(L)]
    wots_pk = wots_pk_from_sig(pk_seed, sigma, 0, 0, leaf_idx, current)

    # XMSS
    auth_off = wots_off + L * N
    auth = [sig[auth_off + j*N : auth_off + (j+1)*N] for j in range(h_param)]
    node = wots_pk
    m_idx = leaf_idx
    for h in range(h_param):
        sib = auth[h]
        parent_idx = m_idx >> 1
        adr = adrsc(0, 0, ADRS_TREE, height=h + 1, tree_index=parent_idx)
        node = H_(pk_seed, adr, node + sib) if (m_idx & 1) == 0 \
               else H_(pk_seed, adr, sib + node)
        m_idx = parent_idx
    return node == pk_root

# ============================================================
#  CLI
# ============================================================

def eprint(*a, **kw): print(*a, file=sys.stderr, **kw)

def abi_encode(seed: bytes, root: bytes, sig: bytes) -> bytes:
    """ABI-encode (bytes32 seed, bytes32 root, bytes sig).
    seed/root are n=16 bytes; place them in the TOP 16 bytes of a bytes32 word
    (bottom 16 = 0) to match the on-chain convention."""
    seed32 = seed + b"\x00" * (32 - N)
    root32 = root + b"\x00" * (32 - N)
    offset = (32).to_bytes(32, "big")   # unused here; real offset = 0x60
    enc  = seed32 + root32
    enc += (0x60).to_bytes(32, "big")
    enc += len(sig).to_bytes(32, "big")
    enc += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return enc

def main():
    p = argparse.ArgumentParser()
    p.add_argument("master_sk_hex")
    p.add_argument("message_hex")
    p.add_argument("sig_counter", nargs="?", default=0, type=int)
    p.add_argument("--height", type=int, default=H_DEFAULT,
                   help="override h' for dev (NIST: 22). Non-default sigs "
                        "won't verify on-chain.")
    p.add_argument("--a", type=int, default=A_DEFAULT,
                   help="override FORS tree height (NIST: 24). Non-default "
                        "sigs won't verify on-chain.")
    args = p.parse_args()

    master_sk = bytes.fromhex(args.master_sk_hex.replace("0x", ""))
    if len(master_sk) != 32:
        eprint("master_sk must be 32 bytes"); sys.exit(1)
    msg_hex = args.message_hex.replace("0x", "")
    if len(msg_hex) % 2:
        msg_hex = "0" + msg_hex
    # Pad to 32 bytes (we sign a bytes32 message — matches our Solidity verifier)
    msg_bytes = bytes.fromhex(msg_hex).rjust(32, b"\x00") if msg_hex \
                 else b"\x00" * 32
    msg_bytes = msg_bytes[-32:]

    h_param = args.height
    a_param = args.a

    # The FIPS 205 digest size m depends on the params. Make sure our M_LEN
    # still accommodates ceil(k·a/8) + ceil(h/8) for overridden values.
    global M_LEN
    M_LEN = ((K * a_param + 7) // 8) + ((h_param + 7) // 8)

    t0 = time.time()
    sk_seed, sk_prf, pk_seed = derive_keys(master_sk)
    eprint(f"  pk_seed = 0x{pk_seed.hex()[:16]}…")
    eprint(f"  Building XMSS root (2^{h_param} leaves)… slow")
    pk_root, _, _ = xmss_root_and_path(pk_seed, sk_seed, 0, 0,
                                       leaf_idx=0, h_param=h_param)
    eprint(f"  pk_root = 0x{pk_root.hex()[:16]}…  ({time.time()-t0:.1f}s)")

    sig = slh_sign(pk_seed, sk_seed, sk_prf, pk_root, msg_bytes,
                   args.sig_counter, h_param, a_param)
    assert slh_verify(pk_seed, pk_root, msg_bytes, sig, h_param, a_param), \
        "local verify failed"
    eprint(f"  Local verify OK.  Sig: {len(sig)} B.  Total: {time.time()-t0:.1f}s")

    print("0x" + abi_encode(pk_seed, pk_root, sig).hex())

if __name__ == "__main__":
    main()
