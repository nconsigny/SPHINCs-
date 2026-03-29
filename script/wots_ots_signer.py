#!/usr/bin/env python3
"""
Standalone WOTS+C one-time signature signer for the WotsOtsAccount contract.

Usage:
    python3 script/wots_ots_signer.py keygen <entropy_hex>
        Output: ABI-encoded (bytes32 pkSeed, bytes32 pkHash, bytes32 skSeed) as hex

    python3 script/wots_ots_signer.py sign <entropy_hex> <message_hex>
        Output: ABI-encoded (bytes32 pkSeed, bytes32 pkHash, bytes sig) as hex
        Re-derives the keypair from entropy and signs statelessly

Parameters: w=16, n=128 bits, len1=32, l=32, targetSum=240, z=0
Signature: 32*16 + 4 = 516 bytes

Standalone ADRS (no layer/tree/keyPair):
  chain hash: (chainIndex << 64) | (position << 32)
  PK compress: (1 << 128)  [WOTS_PK type]
  digest:      0
"""

import sys
import os
import json
import struct
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Constants
# ============================================================

N = 16  # 128 bits
N_MASK = (1 << 256) - (1 << 128)
FULL = (1 << 256) - 1

W = 16
LOG_W = 4
L = 32
LEN1 = 32
TARGET_SUM = 240
W_MASK = 0xF

SIG_SIZE = L * N + 4  # 516 bytes

ADRS_WOTS_PK = 1

# ============================================================
#  Keccak256 Primitives
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

def _keccak_3x32(a: int, b: int, c: int) -> int:
    _BUF96[0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _keccak_4x32(a: int, b: int, c: int, d: int) -> int:
    _BUF128[0:32] = a.to_bytes(32, "big")
    _BUF128[32:64] = b.to_bytes(32, "big")
    _BUF128[64:96] = c.to_bytes(32, "big")
    _BUF128[96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

# ============================================================
#  Tweakable Hash (standalone ADRS — no layer/tree/keyPair)
# ============================================================

def th(seed, adrs, inp):
    return _keccak_3x32(seed, adrs, inp) & N_MASK

def th_multi(seed, adrs, vals):
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

def chain_hash(seed, chain_idx, val, start_pos, steps):
    """Chain hash with standalone ADRS: (chainIndex << 64) | (pos << 32)."""
    base = (chain_idx & 0xFFFFFFFF) << 64
    for step in range(steps):
        pos = start_pos + step
        adrs = base | ((pos & 0xFFFFFFFF) << 32)
        val = _keccak_3x32(seed, adrs, val) & N_MASK
    return val

# ============================================================
#  Key Derivation (standalone)
# ============================================================

def derive_keys(entropy_int):
    ent = keccak256(b"wots_ots_v1" + to_b32(entropy_int))
    seed = keccak256(b"pk_seed" + to_b32(ent)) & N_MASK
    sk_seed = keccak256(b"sk_seed" + to_b32(ent))
    return seed, sk_seed

def wots_secret(sk_seed, chain_idx):
    """Derive secret for chain chain_idx. Standalone: no layer/tree/keyPair."""
    data = to_b32(sk_seed) + b"wots_ots" + to_b4(chain_idx)
    return keccak256(data) & N_MASK

# ============================================================
#  WOTS+C Operations
# ============================================================

def wots_digest(seed, msg_hash, count):
    """Compute WOTS+C constrained digest. ADRS = 0 for standalone."""
    return _keccak_4x32(seed, 0, msg_hash, count)

def extract_digits(d):
    return [(d >> (i * LOG_W)) & W_MASK for i in range(LEN1)]

def wots_find_count(seed, msg_hash):
    """Grind count until digit sum == TARGET_SUM."""
    for count in range(10_000_000):
        d = wots_digest(seed, msg_hash, count)
        digits = extract_digits(d)
        if sum(digits) == TARGET_SUM:
            return count, d, digits
    raise RuntimeError("WOTS+C count grinding failed after 10M attempts")

def wots_keygen(seed, sk_seed):
    """Generate WOTS+C keypair. Returns (sk_list, pkHash)."""
    pk_elements = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, i)
        # Chain from 0 to W-1 = 15 steps
        pk_i = chain_hash(seed, i, sk_i, 0, W - 1)
        pk_elements.append(pk_i)
    # PK compression: thMulti(seed, WOTS_PK_ADRS, endpoints)
    pk_adrs = ADRS_WOTS_PK << 128
    pk_hash = th_multi(seed, pk_adrs, pk_elements)
    return pk_hash

def wots_sign(seed, sk_seed, msg_hash):
    """Sign msg_hash. Returns (sig_bytes, count, digits)."""
    count, d, digits = wots_find_count(seed, msg_hash)
    sigma = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, i)
        # Chain from 0 to digit[i] steps
        sigma_i = chain_hash(seed, i, sk_i, 0, digits[i])
        sigma.append(sigma_i)

    # Pack signature: 32 chain values (16 bytes each) + 4-byte count
    sig = b""
    for s in sigma:
        sig += to_b32(s)[:N]  # take top 16 bytes
    sig += struct.pack(">I", count)
    assert len(sig) == SIG_SIZE, f"sig size {len(sig)} != {SIG_SIZE}"
    return sig

def wots_verify(seed, pk_hash, msg_hash, sig):
    """Verify signature (Python reference). Returns True/False."""
    assert len(sig) == SIG_SIZE
    # Parse sigma values
    sigmas = []
    for i in range(L):
        val = int.from_bytes(sig[i * N : (i + 1) * N], "big") << 128
        sigmas.append(val)
    count = struct.unpack(">I", sig[L * N : L * N + 4])[0]

    # Compute digest
    d = wots_digest(seed, msg_hash, count)
    digits = extract_digits(d)
    if sum(digits) != TARGET_SUM:
        return False

    # Complete chains
    pk_elements = []
    for i in range(L):
        steps = W - 1 - digits[i]
        val = chain_hash(seed, i, sigmas[i], digits[i], steps)
        pk_elements.append(val)

    # PK compression
    pk_adrs = ADRS_WOTS_PK << 128
    computed = th_multi(seed, pk_adrs, pk_elements)
    return computed == pk_hash

# ============================================================
#  ABI Encoding Helpers
# ============================================================

def abi_encode_keygen(seed, pk_hash, sk_seed):
    """ABI-encode (bytes32, bytes32, bytes32)."""
    return to_b32(seed) + to_b32(pk_hash) + to_b32(sk_seed)

def abi_encode_sign(seed, pk_hash, sig):
    """ABI-encode (bytes32 seed, bytes32 pkHash, bytes sig)."""
    # offset for dynamic bytes = 3*32 = 96
    out = to_b32(seed)
    out += to_b32(pk_hash)
    out += to_b32(96)  # offset to sig
    out += to_b32(len(sig))  # sig length
    # pad sig to 32-byte boundary
    padded = sig + b"\x00" * (32 - len(sig) % 32) if len(sig) % 32 != 0 else sig
    out += padded
    return out

# ============================================================
#  CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: wots_ots_signer.py keygen <entropy_hex>", file=sys.stderr)
        print("       wots_ots_signer.py sign <entropy_hex> <message_hex>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "keygen":
        entropy_hex = sys.argv[2]
        entropy = int(entropy_hex, 16)
        seed, sk_seed = derive_keys(entropy)
        pk_hash = wots_keygen(seed, sk_seed)

        result = abi_encode_keygen(seed, pk_hash, sk_seed)
        print("0x" + result.hex())

    elif cmd == "sign":
        # Stateless: rederive keys from entropy, then sign
        entropy_hex = sys.argv[2]
        message_hex = sys.argv[3]
        entropy = int(entropy_hex, 16)
        message = int(message_hex, 16)

        seed, sk_seed = derive_keys(entropy)
        pk_hash = wots_keygen(seed, sk_seed)

        sig = wots_sign(seed, sk_seed, message)

        # Verify locally before returning
        assert wots_verify(seed, pk_hash, message, sig), "Self-verification failed!"

        result = abi_encode_sign(seed, pk_hash, sig)
        print("0x" + result.hex())

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
