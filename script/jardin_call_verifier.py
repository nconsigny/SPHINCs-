#!/usr/bin/env python3
"""
Call JardinForsCVerifier.verifyForsC() directly on Sepolia.
Generates a JARDÍN FORS+C signature, then calls the on-chain verifier via eth_call.

Usage: python3 script/jardin_call_verifier.py
"""

import sys
import os
import json
import requests

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from script.jardin_signer import (
    jardin_derive_keys, build_balanced_tree, jardin_sign,
    to_b32, eprint, N, K, A, A_MASK, Q_MAX
)

# ============================================================
#  Config
# ============================================================

RPC_URL = os.environ.get("SEPOLIA_RPC_URL", "https://rpc.ankr.com/eth_sepolia")
FORSC_VERIFIER = "0x624A925D482DeacA51488aac0732a810810F778f"

# Message to sign
MESSAGE = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

def eth_call(rpc_url, to, data):
    """Perform eth_call and return the result."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
        "id": 1
    }
    resp = requests.post(rpc_url, json=payload, timeout=30)
    result = resp.json()
    if "error" in result:
        eprint(f"  eth_call error: {result['error']}")
        return None
    return result.get("result")

def encode_verify_call(pk_seed, pk_root, message, sig):
    """ABI-encode verifyForsC(bytes32,bytes32,bytes32,bytes) call."""
    from Crypto.Hash import keccak as _k
    h = _k.new(digest_bits=256)
    h.update(b"verifyForsC(bytes32,bytes32,bytes32,bytes)")
    selector = h.digest()[:4]

    # ABI encode: 3 × bytes32 + offset + length + data
    offset = 4 * 32  # offset to bytes data (after 4 fixed params: 3 bytes32 + 1 offset)
    encoded = selector
    encoded += to_b32(pk_seed)
    encoded += to_b32(pk_root)
    encoded += to_b32(message)
    encoded += to_b32(offset)  # offset to bytes
    encoded += to_b32(len(sig))
    padded = sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    encoded += padded
    return "0x" + encoded.hex()

def main():
    rpc_url = os.environ.get("SEPOLIA_RPC_URL", RPC_URL)

    eprint("=== JARDÍN On-Chain Verifier Test ===")

    # Generate keys and signature
    q_leaf = 1
    eprint(f"  Generating signature (q={q_leaf}, Q_MAX={Q_MAX})...")

    pk_seed, sk_seed = jardin_derive_keys(MESSAGE)
    levels, pk_root = build_balanced_tree(pk_seed, sk_seed)
    sig, _, _, _ = jardin_sign(pk_seed, sk_seed, pk_root, levels, MESSAGE, q_leaf)

    eprint(f"  pkSeed = {hex(pk_seed)}")
    eprint(f"  pkRoot = {hex(pk_root)}")
    eprint(f"  sig length = {len(sig)} bytes")

    # Encode call
    calldata = encode_verify_call(pk_seed, pk_root, MESSAGE, sig)
    eprint(f"  Calling verifier at {FORSC_VERIFIER}...")

    result = eth_call(rpc_url, FORSC_VERIFIER, calldata)
    if result:
        # Decode bool result (last byte = 0x01 for true)
        result_clean = result.replace("0x", "").rjust(64, "0")
        valid = int(result_clean, 16) != 0
        eprint(f"  Result: {'VALID' if valid else 'INVALID'}")
        eprint(f"  Raw: {result}")
        print(f"JARDIN FORS+C on-chain verify: {'PASS' if valid else 'FAIL'}")
    else:
        eprint("  eth_call failed!")
        print("JARDIN FORS+C on-chain verify: FAIL (eth_call error)")
        sys.exit(1)

if __name__ == "__main__":
    main()
