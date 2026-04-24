#!/usr/bin/env python3
"""
Cross-validate the forked JARDIN-Keccak-128-24 C signer against the
Python verifier at matching params.

The C and Python signers use DIFFERENT sk-derivation schemes (Python uses
domain-tagged HMACs; C uses SPHINCS+-style PRF with 32-byte JARDIN ADRS),
so they produce different signature BYTES for the same seed.  But the
algorithm is the same — so the Python verify mirror should accept the C
signer's output.

Usage:
    python3 signers/jardin-keccak-128-24/crosscheck.py \\
        <seed_48B_hex> <msg_32B_hex> <optrand_16B_hex> [--h N --a N]
"""
import sys, os, argparse, subprocess

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "script"))
import slh_dsa_keccak_128_24_signer as pysig

def main():
    p = argparse.ArgumentParser()
    p.add_argument("seed_hex")
    p.add_argument("msg_hex")
    p.add_argument("optrand_hex")
    p.add_argument("--h", type=int, default=22)
    p.add_argument("--a", type=int, default=24)
    args = p.parse_args()

    seed = bytes.fromhex(args.seed_hex.removeprefix("0x"))
    msg  = bytes.fromhex(args.msg_hex.removeprefix("0x"))
    optrand = bytes.fromhex(args.optrand_hex.removeprefix("0x"))
    assert len(seed) == 48 and len(msg) == 32 and len(optrand) == 16

    binary = os.path.join(os.path.dirname(__file__), "jardin-keccak-128-24")
    print(f"  C signer @ h={args.h} a={args.a}...")
    out = subprocess.check_output(
        [binary, args.seed_hex, args.msg_hex, args.optrand_hex],
        stderr=subprocess.DEVNULL).decode().strip()
    raw = bytes.fromhex(out)
    pk_seed = raw[:16]; pk_root = raw[16:32]; sig = raw[32:]
    print(f"    pk_seed = 0x{pk_seed.hex()}")
    print(f"    pk_root = 0x{pk_root.hex()}")
    print(f"    sig     = {len(sig)} bytes, first 16 = 0x{sig[:16].hex()}")

    # Python verify mirror takes ints in the JARDIN convention
    # (value in top 16 B of 256-bit word, bottom 16 B zero).
    def to_int(b16): return int.from_bytes(b16 + b"\x00" * 16, "big")
    pk_seed_i = to_int(pk_seed)
    pk_root_i = to_int(pk_root)
    msg_i     = int.from_bytes(msg, "big")

    ok = pysig.slh_verify(pk_seed_i, pk_root_i, msg_i, sig,
                          h_param=args.h, a_param=args.a)
    print(f"\n  Python verify: {'OK' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
