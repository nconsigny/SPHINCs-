#!/usr/bin/env python3
"""
Cross-validate the forked C signer (slhdsa-sha2-128-24) against the Python
SHA-2 signer (script/slh_dsa_sha2_128_24_signer.py) at whatever params the
C binary was built with.

Both signers must produce the SAME pk_seed, pk_root, and signature bytes
when fed identical inputs (seed, message, optrand).  If they diverge we
know one side has a bug.

Assumes this script runs from the repo root.

Usage:
    python3 signers/sphincsplus-128-24/crosscheck.py \\
        <seed_48B_hex> <message_hex> <optrand_16B_hex> [--h N --a N]
"""
import sys, os, argparse, subprocess

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "script"))

# Import the Python signer module (bypasses its argparse CLI)
import slh_dsa_sha2_128_24_signer as pysig

def py_sign_with_raw_seeds(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes,
                           message: bytes, optrand: bytes,
                           h_param: int, a_param: int):
    """Run the Python signer with pre-derived seeds (bypass JARDIN HMAC)."""
    # Match C: M_LEN is recomputed per params.
    pysig.M_LEN = ((pysig.K * a_param + 7) // 8) + ((h_param + 7) // 8)

    # Build pk_root via full tree-hash (slow at full params)
    pk_root, _, _ = pysig.xmss_root_and_path(
        pk_seed, sk_seed, 0, 0, leaf_idx=0, h_param=h_param)

    # NIST-style sign uses PRFmsg(sk_prf, optrand, M) as R.  Our current
    # Python signer picks optrand from sig_counter; bypass it.
    R = pysig.PRFmsg(sk_prf, optrand, message)
    digest = pysig.Hmsg(R, pk_seed, pk_root, message)
    md, leaf_idx = pysig.digest_indices(digest, h_param, a_param)

    # FORS
    fors_pieces, fors_roots = [], []
    for t in range(pysig.K):
        auth, r, sk = pysig.build_fors_subtree(
            pk_seed, sk_seed, leaf_idx, t, md[t], a_param)
        fors_pieces.append((sk, auth))
        fors_roots.append(r)
    fors_pk = pysig.T_l(
        pk_seed,
        pysig.adrsc(0, 0, pysig.ADRS_FORS_ROOTS, kp=leaf_idx),
        b"".join(fors_roots))

    xmss_root, xmss_auth, wots_sks = pysig.xmss_root_and_path(
        pk_seed, sk_seed, 0, 0, leaf_idx, h_param)
    assert xmss_root == pk_root

    sigma = pysig.wots_sign(pk_seed, wots_sks, 0, 0, leaf_idx, fors_pk)

    out = bytearray()
    out += R
    for sk, auth in fors_pieces:
        out += sk
        for node in auth:
            out += node
    for s in sigma:
        out += s
    for node in xmss_auth:
        out += node
    return pk_seed, pk_root, bytes(out)

def run_c_signer(seed_hex, msg_hex, optrand_hex):
    binary = os.path.join(os.path.dirname(__file__), "slhdsa-sha2-128-24")
    out = subprocess.check_output(
        [binary, seed_hex, msg_hex, optrand_hex],
        stderr=subprocess.DEVNULL).decode().strip()
    raw = bytes.fromhex(out)
    pk_seed = raw[:16]
    pk_root = raw[16:32]
    sig     = raw[32:]
    return pk_seed, pk_root, sig

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
    assert len(seed) == 48 and len(optrand) == 16

    sk_seed, sk_prf, pk_seed = seed[:16], seed[16:32], seed[32:48]

    print(f"  C signer ({args.h=}, {args.a=})...")
    c_pk_seed, c_pk_root, c_sig = run_c_signer(
        args.seed_hex, args.msg_hex, args.optrand_hex)
    print(f"    pk_seed = 0x{c_pk_seed.hex()}")
    print(f"    pk_root = 0x{c_pk_root.hex()}")
    print(f"    sig     = {len(c_sig)} bytes, first 16 = 0x{c_sig[:16].hex()}")

    print(f"  Python signer (same params)...")
    py_pk_seed, py_pk_root, py_sig = py_sign_with_raw_seeds(
        sk_seed, sk_prf, pk_seed, msg, optrand, args.h, args.a)
    print(f"    pk_seed = 0x{py_pk_seed.hex()}")
    print(f"    pk_root = 0x{py_pk_root.hex()}")
    print(f"    sig     = {len(py_sig)} bytes, first 16 = 0x{py_sig[:16].hex()}")

    ok = (c_pk_seed == py_pk_seed and c_pk_root == py_pk_root and c_sig == py_sig)
    print(f"\n  MATCH: {ok}")
    if not ok:
        if c_pk_seed != py_pk_seed: print("    pk_seed differs")
        if c_pk_root != py_pk_root: print("    pk_root differs")
        if c_sig     != py_sig:
            print("    sig differs; first mismatch at byte "
                  f"{next(i for i in range(min(len(c_sig),len(py_sig))) if c_sig[i] != py_sig[i])}")
        sys.exit(1)

if __name__ == "__main__":
    main()
