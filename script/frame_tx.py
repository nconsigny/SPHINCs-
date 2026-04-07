#!/usr/bin/env python3
"""
EIP-8141 Frame Transaction PoC for SPHINCS+ C6.

Sends a type-6 frame transaction on the ethrex testnet:
  Frame 0 (VERIFY): calls the SPHINCS+ verifier to validate the signature
  Frame 1 (SENDER): executes the actual transfer

Usage:
    python3 script/frame_tx.py deploy  --rpc <url>  [--dev-key <hex>]
    python3 script/frame_tx.py send    --rpc <url>  --account <addr> --to <addr> --value 0.001
"""

import sys
import os
import json
import argparse
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import (sign_variant, sign_with_known_keys, derive_keys,
                     keccak256, to_b32, N_MASK, VARIANTS)

import requests

# ============================================================
#  Constants
# ============================================================

FRAME_TX_TYPE = 0x06
MODE_VERIFY = 1
MODE_SENDER = 2

DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# ============================================================
#  RLP Encoding
# ============================================================

def rlp_encode_uint(val):
    if val == 0:
        return b'\x80'
    data = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    if len(data) == 1 and data[0] < 0x80:
        return data
    return _rlp_length_prefix(data, 0x80)

def rlp_encode_bytes(data):
    if isinstance(data, int):
        return rlp_encode_uint(data)
    if len(data) == 1 and data[0] < 0x80:
        return data
    return _rlp_length_prefix(data, 0x80)

def rlp_encode_list(items):
    payload = b''.join(items)
    return _rlp_length_prefix(payload, 0xc0)

def _rlp_length_prefix(data, offset):
    length = len(data)
    if length < 56:
        return bytes([offset + length]) + data
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes + data

def rlp_encode_address(addr_hex):
    addr = bytes.fromhex(addr_hex.replace('0x', ''))
    assert len(addr) == 20
    return rlp_encode_bytes(addr)

# ============================================================
#  Frame Transaction Builder
# ============================================================

def build_frame_tx(chain_id, nonce, sender, frames,
                   max_priority_fee=1_000_000_000,
                   max_fee=2_000_000_000,
                   max_blob_fee=0,
                   blob_hashes=None):
    """Build an EIP-8141 type-6 frame transaction (unsigned payload)."""
    if blob_hashes is None:
        blob_hashes = []

    encoded_frames = []
    for mode, target, gas_limit, data in frames:
        if target is None:
            target_rlp = rlp_encode_bytes(b'')  # null = defaults to sender
        else:
            target_rlp = rlp_encode_address(target)
        frame_rlp = rlp_encode_list([
            rlp_encode_uint(mode),
            target_rlp,
            rlp_encode_uint(gas_limit),
            rlp_encode_bytes(data),
        ])
        encoded_frames.append(frame_rlp)

    blob_hash_items = [rlp_encode_bytes(h) for h in blob_hashes]

    payload = rlp_encode_list([
        rlp_encode_uint(chain_id),
        rlp_encode_uint(nonce),
        rlp_encode_address(sender),
        rlp_encode_list(encoded_frames),
        rlp_encode_uint(max_priority_fee),
        rlp_encode_uint(max_fee),
        rlp_encode_uint(max_blob_fee),
        rlp_encode_list(blob_hash_items),
    ])
    return payload

def compute_sig_hash(tx_payload):
    """Compute the signature hash for a frame tx (keccak of type prefix + payload).
    Note: VERIFY frame data is elided per EIP-8141."""
    return keccak256(bytes([FRAME_TX_TYPE]) + tx_payload)

# ============================================================
#  Helpers
# ============================================================

def rpc_call(url, method, params):
    resp = requests.post(url, json={
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    }, timeout=30)
    result = resp.json()
    if "error" in result:
        print(f"RPC error ({method}): {result['error']}", file=sys.stderr)
        return None
    return result.get("result")

def get_nonce(rpc, addr):
    result = rpc_call(rpc, "eth_getTransactionCount", [addr, "latest"])
    return int(result, 16) if result else 0

def get_chain_id(rpc):
    result = rpc_call(rpc, "eth_chainId", [])
    return int(result, 16) if result else 1729

def get_balance(rpc, addr):
    result = rpc_call(rpc, "eth_getBalance", [addr, "latest"])
    return int(result, 16) if result else 0

def send_raw_tx(rpc, raw_hex):
    result = rpc_call(rpc, "eth_sendRawTransaction", [raw_hex])
    return result

# ============================================================
#  Commands
# ============================================================

def cmd_deploy(args):
    """Deploy the C6 verifier contract on the frame testnet."""
    rpc = args.rpc
    dev_key = args.dev_key.replace("0x", "")
    chain_id = get_chain_id(rpc)
    print(f"Chain ID: {chain_id}")

    # Generate SPHINCS+ keypair
    print("Generating C6 keypair...")
    entropy_input = bytes.fromhex(dev_key) + b"c6"
    keygen_msg = keccak256(b"sphincs_keygen" + entropy_input)
    seed, root, _sig = sign_variant("c6", keygen_msg)
    print(f"  pkSeed: 0x{seed:064x}")
    print(f"  pkRoot: 0x{root:064x}")

    # Deploy verifier using cast
    import subprocess
    # Get the creation bytecode
    artifact_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "out", "SPHINCs-C6Asm.sol", "SphincsC6Asm.json")
    with open(artifact_path) as f:
        artifact = json.load(f)
    creation_code = artifact["bytecode"]["object"]

    # Constructor args: (bytes32 pkSeed, bytes32 pkRoot)
    from eth_abi import encode
    constructor_args = encode(["bytes32", "bytes32"],
                              [seed.to_bytes(32, "big"), root.to_bytes(32, "big")])
    deploy_data = creation_code + constructor_args.hex()

    print(f"\nDeploying C6 verifier (via legacy tx from dev key)...")
    proc = subprocess.run(
        ["cast", "send",
         "--rpc-url", rpc, "--private-key", "0x" + dev_key,
         "--create", deploy_data],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode == 0:
        # Parse contract address from output
        for line in proc.stdout.split('\n'):
            if 'contractAddress' in line:
                addr = line.split()[-1]
                print(f"  Verifier deployed at: {addr}")
                # Save
                info = {
                    "chain_id": chain_id,
                    "verifier": addr,
                    "seed": f"0x{seed:064x}",
                    "root": f"0x{root:064x}",
                    "rpc": rpc,
                }
                info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          ".frame_c6_deploy.json")
                with open(info_path, "w") as f:
                    json.dump(info, f, indent=2)
                print(f"  Saved to {info_path}")
                return
        print(proc.stdout)
    else:
        print(f"Deploy failed: {proc.stderr}", file=sys.stderr)


def cmd_send(args):
    """Send a type-6 frame transaction with SPHINCS+ C6 verification."""
    rpc = args.rpc
    chain_id = get_chain_id(rpc)
    sender = args.account
    to = args.to
    value_wei = int(float(args.value) * 1e18)

    print(f"=== EIP-8141 Frame Transaction (SPHINCS+ C6) ===")
    print(f"Chain: {chain_id}, Sender: {sender}")
    print(f"To: {to}, Value: {args.value} ETH")

    nonce = get_nonce(rpc, sender)
    balance = get_balance(rpc, sender)
    print(f"Nonce: {nonce}, Balance: {balance / 1e18:.4f} ETH")

    # Load verifier info
    info_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".frame_c6_deploy.json")
    if not os.path.exists(info_path):
        print("Error: No deployment info. Run 'deploy' first.", file=sys.stderr)
        sys.exit(1)
    with open(info_path) as f:
        deploy_info = json.load(f)
    verifier = deploy_info["verifier"]
    print(f"Verifier: {verifier}")

    # EIP-8141 Frame layout (matching working ethrex pattern):
    #   Frame 0 (VERIFY mode=1): call the sender account itself
    #     - target = sender (frame account with SPHINCS+ verify + APPROVE)
    #     - data = ABI-encoded verify(bytes32, bytes) call forwarded to verifier
    #     - mode = 1 (VERIFY)
    #
    #   Frame 1 (SENDER mode=2): ETH transfer
    #     - target = sender (executes as the account)
    #     - data = empty for plain ETH, or execute(to, value, data)

    # Per EIP-8141: sig_hash computed with VERIFY frame data elided
    frames_for_hash = [
        (MODE_VERIFY, sender, 500_000, b''),  # target = sender account
        (MODE_SENDER, sender, 50_000, b''),   # target = sender account
    ]

    tx_payload_for_hash = build_frame_tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        frames=frames_for_hash,
        max_priority_fee=1_000_000_000,
        max_fee=2_000_000_000,
    )

    sig_hash = compute_sig_hash(tx_payload_for_hash)
    print(f"Sig hash: 0x{sig_hash:064x}")

    # Sign with SPHINCS+ C6
    print("Signing with SPHINCS+ C6...")
    seed_int = int(deploy_info["seed"], 16)
    root_int = int(deploy_info["root"], 16)

    dev_key = args.dev_key.replace("0x", "") if args.dev_key else DEV_KEY
    entropy_input = bytes.fromhex(dev_key) + b"c6"
    keygen_msg = keccak256(b"sphincs_keygen" + entropy_input)
    _, sk_seed = derive_keys(keygen_msg)

    sphincs_sig = sign_with_known_keys("c6", sig_hash, seed_int, sk_seed, root_int)
    print(f"  Signature: {len(sphincs_sig)} bytes")

    # Build VERIFY frame data: verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 sigHash, bytes sig)
    # The frame account forwards this directly to the shared verifier
    from eth_abi import encode
    verify_selector = keccak256(b"verify(bytes32,bytes32,bytes32,bytes)").to_bytes(32, "big")[:4]
    verify_calldata = verify_selector + encode(
        ["bytes32", "bytes32", "bytes32", "bytes"],
        [seed_int.to_bytes(32, "big"), root_int.to_bytes(32, "big"),
         sig_hash.to_bytes(32, "big"), sphincs_sig]
    )

    # Final frames with actual signature
    frames_final = [
        (MODE_VERIFY, sender, 500_000, verify_calldata),  # target = sender
        (MODE_SENDER, sender, 50_000, b''),                # target = sender
    ]

    final_payload = build_frame_tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        frames=frames_final,
        max_priority_fee=1_000_000_000,
        max_fee=2_000_000_000,
    )

    raw_tx = bytes([FRAME_TX_TYPE]) + final_payload
    raw_hex = "0x" + raw_tx.hex()
    print(f"Raw tx: {len(raw_tx)} bytes")
    print(f"  VERIFY frame data: {len(verify_calldata)} bytes")

    # Submit
    print("\nSubmitting frame transaction...")
    tx_hash = send_raw_tx(rpc, raw_hex)
    if tx_hash:
        print(f"  TX hash: {tx_hash}")

        # Poll for receipt
        import time
        for _ in range(10):
            time.sleep(2)
            receipt = rpc_call(rpc, "eth_getTransactionReceipt", [tx_hash])
            if receipt:
                print(f"  Block: {int(receipt.get('blockNumber', '0x0'), 16)}")
                print(f"  Status: {receipt.get('status', '?')}")
                if 'frameReceipts' in receipt:
                    for i, fr in enumerate(receipt['frameReceipts']):
                        print(f"  Frame {i}: status={fr.get('status')}")
                break
        else:
            print("  (receipt not yet available — tx may still be pending)")

        print("\nFrame transaction submitted!")
    else:
        print("Submission failed.")


# ============================================================
#  Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="EIP-8141 Frame Transaction PoC (SPHINCS+ C6)")
    sub = parser.add_subparsers(dest="command")

    p_deploy = sub.add_parser("deploy", help="Deploy C6 verifier on frame testnet")
    p_deploy.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    p_deploy.add_argument("--dev-key", default="0x" + DEV_KEY)

    p_send = sub.add_parser("send", help="Send a frame transaction")
    p_send.add_argument("--rpc", default="https://demo.eip-8141.ethrex.xyz/rpc")
    p_send.add_argument("--account", required=True, help="Sender account address")
    p_send.add_argument("--to", required=True, help="Recipient address")
    p_send.add_argument("--value", default="0.001", help="Value in ETH")
    p_send.add_argument("--dev-key", default="0x" + DEV_KEY)

    args = parser.parse_args()
    if args.command == "deploy":
        cmd_deploy(args)
    elif args.command == "send":
        cmd_send(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
