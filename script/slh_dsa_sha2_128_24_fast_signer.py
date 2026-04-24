#!/usr/bin/env python3
"""
Fast SLH-DSA-SHA2-128-24 signer — wraps the forked sphincsplus C binary
(signers/sphincsplus-128-24/slhdsa-sha2-128-24) and emits the same
ABI-encoded (bytes32 seed, bytes32 root, bytes sig) format used by the
pure-Python `slh_dsa_sha2_128_24_signer.py`.

The C binary produces a real NIST-params signature (h=22, d=1, a=24, k=6)
in ~1-3 minutes; our pure-Python signer takes hours for the same task.
Use this wrapper for Forge FFI tests and fixture generation.

A disk cache is used: if a fixture with the same inputs is already on
disk, we return it immediately.

Usage:
    python3 script/slh_dsa_sha2_128_24_fast_signer.py \\
        <master_sk_hex> <message_hex> [sig_counter]

Same CLI shape as the pure-Python signer. Key derivation uses the JARDIN
HMAC-SHA-512 scheme for parity; the 48-byte (sk_seed‖sk_prf‖pk_seed) seed
is handed to the C binary.
"""

import sys, os, json, hashlib, hmac, subprocess, argparse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN_PATH  = os.path.join(REPO_ROOT, "signers/sphincsplus-128-24/slhdsa-sha2-128-24")
CACHE_DIR = os.path.join(REPO_ROOT, "signers/sphincsplus-128-24/.cache")

N       = 16
SIG_LEN = 3856

def eprint(*a, **kw): print(*a, file=sys.stderr, **kw)

def hmac512(key, msg):
    return hmac.new(key, msg, hashlib.sha512).digest()

def derive_seed_48(master_sk: bytes) -> bytes:
    """Mirrors the JARDIN derivation used by slh_dsa_sha2_128_24_signer.py."""
    sk_seed = hmac512(master_sk, b"JARDIN/SLH2128_24/SKSEED")[:N]
    sk_prf  = hmac512(master_sk, b"JARDIN/SLH2128_24/SKPRF" )[:N]
    pk_seed = hmac512(master_sk, b"JARDIN/SLH2128_24/PKSEED")[:N]
    return sk_seed + sk_prf + pk_seed

def abi_encode(seed16: bytes, root16: bytes, sig: bytes) -> bytes:
    seed32 = seed16 + b"\x00" * (32 - N)
    root32 = root16 + b"\x00" * (32 - N)
    enc  = seed32 + root32
    enc += (0x60).to_bytes(32, "big")
    enc += len(sig).to_bytes(32, "big")
    enc += sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return enc

def cache_key(master_sk_hex: str, message_hex: str, sig_counter: int) -> str:
    h = hashlib.sha256()
    h.update(master_sk_hex.lower().encode())
    h.update(b"|")
    h.update(message_hex.lower().encode())
    h.update(b"|")
    h.update(str(sig_counter).encode())
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("master_sk_hex")
    p.add_argument("message_hex")
    p.add_argument("sig_counter", nargs="?", default=0, type=int)
    p.add_argument("--no-cache", action="store_true")
    args = p.parse_args()

    if not os.path.isfile(BIN_PATH):
        eprint(f"  C binary not found at {BIN_PATH}")
        eprint(f"  Build with:  (cd signers/sphincsplus-128-24 && make)")
        sys.exit(1)

    master_sk = bytes.fromhex(args.master_sk_hex.removeprefix("0x"))
    if len(master_sk) != 32:
        eprint("master_sk must be 32 bytes"); sys.exit(1)

    msg_hex = args.message_hex.removeprefix("0x")
    if len(msg_hex) % 2: msg_hex = "0" + msg_hex
    # C CLI takes message as raw hex bytes; pass through as-is.

    # optrand for deterministic test sigs: derive from sig_counter
    optrand = args.sig_counter.to_bytes(4, "big") + b"\x00" * (N - 4)

    # Disk cache
    os.makedirs(CACHE_DIR, exist_ok=True)
    key = cache_key(args.master_sk_hex, args.message_hex, args.sig_counter)
    cache_path = os.path.join(CACHE_DIR, f"{key}.hex")

    if not args.no_cache and os.path.isfile(cache_path):
        eprint(f"  [cache hit] {cache_path}")
        with open(cache_path, "r") as f:
            print(f.read().strip())
        return

    seed48 = derive_seed_48(master_sk)

    eprint(f"  invoking C signer (h=22, a=24 — ~1-3 min)...")
    result = subprocess.run(
        [BIN_PATH, seed48.hex(), msg_hex, optrand.hex()],
        capture_output=True, text=True)
    if result.returncode != 0:
        eprint(f"  C signer failed (rc={result.returncode}):")
        eprint(result.stderr)
        sys.exit(1)

    raw = bytes.fromhex(result.stdout.strip())
    if len(raw) != 2 * N + SIG_LEN:
        eprint(f"  unexpected C output size: {len(raw)} != {2*N + SIG_LEN}")
        sys.exit(1)
    pk_seed = raw[:N]
    pk_root = raw[N:2*N]
    sig     = raw[2*N:]

    eprint(f"  pk_seed = 0x{pk_seed.hex()[:16]}…")
    eprint(f"  pk_root = 0x{pk_root.hex()[:16]}…")
    eprint(f"  sig: {len(sig)} bytes")

    abi_hex = "0x" + abi_encode(pk_seed, pk_root, sig).hex()
    with open(cache_path, "w") as f:
        f.write(abi_hex + "\n")
    eprint(f"  cached at {cache_path}")
    print(abi_hex)

if __name__ == "__main__":
    main()
