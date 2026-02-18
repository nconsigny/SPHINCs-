#!/usr/bin/env python3
"""
Send an ERC-4337 UserOperation with hybrid ECDSA + SPHINCS+ signatures.

Usage:
    # Step 1: Deploy factory (via forge script)
    # Step 2: Create account and fund it
    python3 script/send_userop.py create --factory <factory_addr> --ecdsa-key <hex_privkey> --variant c2
    # Step 3: Send a UserOp
    python3 script/send_userop.py send --account <account_addr> --ecdsa-key <hex_privkey> --to <recipient> --value 0.001 --variant c2

Environment:
    PIMLICO_API_KEY  - Pimlico bundler API key
    SEPOLIA_RPC_URL  - (optional) Sepolia RPC URL, defaults to Pimlico
"""

import sys
import os
import json
import time
import argparse
import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_abi import encode, decode

# Add script dir to path so we can import signer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import sign_variant, keccak256, to_b32, N_MASK

# ============================================================
#  Constants
# ============================================================

ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111  # Sepolia

# ============================================================
#  Helpers
# ============================================================

def get_pimlico_url():
    api_key = os.environ.get("PIMLICO_API_KEY")
    if not api_key:
        # Try loading from .env
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PIMLICO_API_KEY="):
                        api_key = line.split("=", 1)[1].strip()
                        break
    if not api_key:
        print("Error: PIMLICO_API_KEY not set", file=sys.stderr)
        sys.exit(1)
    return f"https://api.pimlico.io/v2/{CHAIN_ID}/rpc?apikey={api_key}"


def get_eth_rpc():
    """Get a standard Ethereum RPC (not bundler) for eth_call etc."""
    rpc = os.environ.get("ETH_RPC_URL")
    if rpc:
        return rpc
    # Fallback to public Sepolia
    return "https://rpc.sepolia.org"


def rpc_call(url, method, params):
    """Make a JSON-RPC call."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    resp = requests.post(url, json=payload, timeout=30)
    result = resp.json()
    if "error" in result:
        print(f"RPC error ({method}): {result['error']}", file=sys.stderr)
        return None
    return result.get("result")


def eth_call(rpc_url, to, data):
    """eth_call helper."""
    return rpc_call(rpc_url, "eth_call", [{"to": to, "data": data}, "latest"])


def hex_to_int(h):
    if h is None:
        return 0
    return int(h, 16)


def to_hex(val, length=32):
    """Convert int to 0x-prefixed hex of given byte length."""
    return "0x" + val.to_bytes(length, "big").hex()


def keccak_bytes(data: bytes) -> bytes:
    """keccak256 returning bytes."""
    return keccak256(data).to_bytes(32, "big")


# ============================================================
#  SPHINCS+ Key Derivation (must match signer.py)
# ============================================================

def derive_sphincs_keys(ecdsa_privkey_hex, variant):
    """Derive deterministic SPHINCS+ seed/root from ECDSA key + variant."""
    # Use ECDSA private key + variant as entropy source
    entropy_input = bytes.fromhex(ecdsa_privkey_hex) + variant.encode()
    entropy = keccak256(entropy_input)

    # Derive seed and sk_seed the same way signer.py does
    seed = keccak256(b"pk_seed" + entropy.to_bytes(32, "big")) & N_MASK
    sk_seed = keccak256(b"sk_seed" + entropy.to_bytes(32, "big"))

    return seed, sk_seed, entropy


def get_sphincs_root(ecdsa_privkey_hex, variant):
    """Generate SPHINCS+ keypair and return (seed, root).
    This calls the signer to do the full keygen."""
    # We use a deterministic message derived from the private key
    # to produce consistent seed/root for this key+variant combo
    entropy_input = bytes.fromhex(ecdsa_privkey_hex) + variant.encode()
    message_int = keccak256(b"sphincs_keygen" + entropy_input)

    seed, root, _sig = sign_variant(variant, message_int)
    return seed, root


# ============================================================
#  UserOp Construction
# ============================================================

def pack_user_op_for_hash(user_op):
    """Pack UserOp for hashing (per ERC-4337 spec).
    hash = keccak256(abi.encode(
        keccak256(pack(userOp)),  // without signature and paymasterSignature
        entryPoint,
        chainId
    ))
    """
    # Pack the inner hash: sender, nonce, keccak(initCode), keccak(callData),
    # accountGasLimits, preVerificationGas, gasFees, keccak(paymasterAndData)
    init_code = bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b""
    call_data = bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b""
    pm_data = bytes.fromhex(user_op["paymasterAndData"][2:]) if user_op["paymasterAndData"] != "0x" else b""

    inner = encode(
        ["address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
        [
            bytes.fromhex(user_op["sender"][2:]),  # address
            int(user_op["nonce"], 16),
            keccak_bytes(init_code),
            keccak_bytes(call_data),
            bytes.fromhex(user_op["accountGasLimits"][2:]),
            int(user_op["preVerificationGas"], 16),
            bytes.fromhex(user_op["gasFees"][2:]),
            keccak_bytes(pm_data),
        ]
    )

    inner_hash = keccak_bytes(inner)

    outer = encode(
        ["bytes32", "address", "uint256"],
        [inner_hash, bytes.fromhex(ENTRYPOINT_V09[2:]), CHAIN_ID]
    )

    return keccak_bytes(outer)


def build_execute_calldata(to_addr, value_wei, data=b""):
    """Encode SphincsAccount.execute(address, uint256, bytes) call."""
    selector = keccak_bytes(b"execute(address,uint256,bytes)")[:4]
    params = encode(
        ["address", "uint256", "bytes"],
        [bytes.fromhex(to_addr[2:]), value_wei, data]
    )
    return selector + params


def sign_user_op(user_op_hash_bytes, ecdsa_privkey_hex, sphincs_sig_bytes):
    """Create hybrid signature: abi.encode(ecdsaSig, sphincsSig)."""
    # ECDSA sign the userOpHash
    acct = Account.from_key(bytes.fromhex(ecdsa_privkey_hex))
    signed = acct.signHash(user_op_hash_bytes)

    # Pack ECDSA sig as (r, s, v) = 65 bytes
    ecdsa_sig = (
        signed.r.to_bytes(32, "big") +
        signed.s.to_bytes(32, "big") +
        signed.v.to_bytes(1, "big")
    )

    # ABI-encode the hybrid signature
    hybrid = encode(["bytes", "bytes"], [ecdsa_sig, sphincs_sig_bytes])
    return hybrid


# ============================================================
#  Commands
# ============================================================

def cmd_create(args):
    """Create a new SPHINCS+ account via the factory."""
    print("=== Creating SPHINCS+ 4337 Account ===")

    ecdsa_key = args.ecdsa_key.replace("0x", "")
    acct = Account.from_key(bytes.fromhex(ecdsa_key))
    print(f"ECDSA owner: {acct.address}")

    # Generate SPHINCS+ keypair
    print(f"Generating SPHINCS+ keypair (variant {args.variant})... this takes ~10s")
    seed, root = get_sphincs_root(ecdsa_key, args.variant)
    print(f"  pkSeed: {to_hex(seed)}")
    print(f"  pkRoot: {to_hex(root)}")

    variant_num = {"c2": 2, "c3": 3}[args.variant]

    # Compute counterfactual address
    factory = args.factory
    rpc = get_eth_rpc()

    # Call factory.getAddress(ecdsaOwner, pkSeed, pkRoot, variant)
    selector = keccak_bytes(b"getAddress(address,bytes32,bytes32,uint8)")[:4]
    calldata = selector + encode(
        ["address", "bytes32", "bytes32", "uint8"],
        [bytes.fromhex(acct.address[2:]), seed.to_bytes(32, "big"), root.to_bytes(32, "big"), variant_num]
    )
    result = eth_call(rpc, factory, "0x" + calldata.hex())
    if result:
        account_addr = "0x" + result[26:66]
        print(f"\nCounterfactual account address: {account_addr}")
        print(f"\nTo deploy, call factory.createAccount() with a funded EOA:")
        print(f"  cast send {factory} 'createAccount(address,bytes32,bytes32,uint8)' \\")
        print(f"    {acct.address} {to_hex(seed)} {to_hex(root)} {variant_num} \\")
        print(f"    --rpc-url ${{SEPOLIA_RPC_URL}} --private-key 0x{ecdsa_key}")
        print(f"\nThen fund the account: cast send {account_addr} --value 0.01ether ...")
    else:
        print("Could not compute address. Is the factory deployed?")

    # Save keypair info for later use
    keypair_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), f".sphincs_keypair_{args.variant}.json")
    with open(keypair_file, "w") as f:
        json.dump({
            "variant": args.variant,
            "seed": to_hex(seed),
            "root": to_hex(root),
            "ecdsa_owner": acct.address,
            "factory": factory,
        }, f, indent=2)
    print(f"\nKeypair saved to {keypair_file}")


def cmd_send(args):
    """Send a UserOp with hybrid ECDSA + SPHINCS+ signature."""
    print("=== Sending Hybrid UserOp ===")

    ecdsa_key = args.ecdsa_key.replace("0x", "")
    acct = Account.from_key(bytes.fromhex(ecdsa_key))
    bundler_url = get_pimlico_url()
    rpc = get_eth_rpc()

    print(f"ECDSA signer: {acct.address}")
    print(f"Account: {args.account}")
    print(f"To: {args.to}")
    print(f"Value: {args.value} ETH")

    value_wei = int(float(args.value) * 1e18)

    # Build callData (execute)
    call_data = build_execute_calldata(args.to, value_wei)

    # Get nonce
    nonce_result = rpc_call(bundler_url, "eth_call", [{
        "to": ENTRYPOINT_V09,
        "data": "0x" + (keccak_bytes(b"getNonce(address,uint192)")[:4] +
                        encode(["address", "uint192"], [bytes.fromhex(args.account[2:]), 0])).hex()
    }, "latest"])
    nonce = hex_to_int(nonce_result) if nonce_result else 0

    # Get gas prices
    gas_prices = rpc_call(bundler_url, "pimlico_getUserOperationGasPrice", [])
    if gas_prices and "fast" in gas_prices:
        max_fee = gas_prices["fast"]["maxFeePerGas"]
        max_priority = gas_prices["fast"]["maxPriorityFeePerGas"]
    else:
        max_fee = "0x" + (50 * 10**9).to_bytes(16, "big").hex()  # 50 gwei
        max_priority = "0x" + (2 * 10**9).to_bytes(16, "big").hex()  # 2 gwei

    # Pack gas fields
    # accountGasLimits = uint128(verificationGasLimit) || uint128(callGasLimit)
    ver_gas = 2_000_000   # high to account for SPHINCS+ verification
    call_gas = 100_000
    account_gas_limits = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()

    # gasFees = uint128(maxPriorityFeePerGas) || uint128(maxFeePerGas)
    max_priority_int = hex_to_int(max_priority) if isinstance(max_priority, str) else max_priority
    max_fee_int = hex_to_int(max_fee) if isinstance(max_fee, str) else max_fee
    gas_fees = "0x" + (max_priority_int.to_bytes(16, "big") + max_fee_int.to_bytes(16, "big")).hex()

    pre_ver_gas = 200_000

    # Build UserOp with dummy signature for gas estimation
    user_op = {
        "sender": args.account,
        "nonce": hex(nonce),
        "initCode": "0x",
        "callData": "0x" + call_data.hex(),
        "accountGasLimits": account_gas_limits,
        "preVerificationGas": hex(pre_ver_gas),
        "gasFees": gas_fees,
        "paymasterAndData": "0x",
        "signature": "0x" + ("00" * 1000),  # dummy sig for estimation
    }

    print("\nEstimating gas...")
    gas_est = rpc_call(bundler_url, "eth_estimateUserOperationGas", [user_op, ENTRYPOINT_V09])
    if gas_est:
        print(f"  Gas estimates: {json.dumps(gas_est, indent=2)}")
        # Update gas limits from estimation
        ver_gas = hex_to_int(gas_est.get("verificationGasLimit", hex(ver_gas)))
        call_gas = hex_to_int(gas_est.get("callGasLimit", hex(call_gas)))
        pre_ver_gas = hex_to_int(gas_est.get("preVerificationGas", hex(pre_ver_gas)))

        # Add safety margins
        ver_gas = int(ver_gas * 1.5)
        call_gas = int(call_gas * 1.5)

        user_op["accountGasLimits"] = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()
        user_op["preVerificationGas"] = hex(pre_ver_gas)

    # Compute userOpHash
    user_op_hash = pack_user_op_for_hash(user_op)
    print(f"\nUserOp hash: 0x{user_op_hash.hex()}")

    # Sign with SPHINCS+
    user_op_hash_int = int.from_bytes(user_op_hash, "big")
    print(f"Generating SPHINCS+ signature (variant {args.variant})... this takes ~10s")
    _seed, _root, sphincs_sig = sign_variant(args.variant, user_op_hash_int)
    print(f"  SPHINCS+ sig: {len(sphincs_sig)} bytes")

    # Create hybrid signature
    hybrid_sig = sign_user_op(user_op_hash, ecdsa_key, sphincs_sig)
    user_op["signature"] = "0x" + hybrid_sig.hex()
    print(f"  Hybrid sig total: {len(hybrid_sig)} bytes")

    # Submit
    print("\nSubmitting UserOp to bundler...")
    result = rpc_call(bundler_url, "eth_sendUserOperation", [user_op, ENTRYPOINT_V09])
    if result:
        print(f"UserOp hash (bundler): {result}")
        print("\nWaiting for receipt...")
        for _ in range(60):
            receipt = rpc_call(bundler_url, "eth_getUserOperationReceipt", [result])
            if receipt:
                print(f"\nTransaction mined!")
                print(f"  TX hash: {receipt.get('receipt', {}).get('transactionHash', 'unknown')}")
                print(f"  Block:   {receipt.get('receipt', {}).get('blockNumber', 'unknown')}")
                print(f"  Success: {receipt.get('success', 'unknown')}")
                print(f"  Gas used: {receipt.get('actualGasUsed', 'unknown')}")
                return
            time.sleep(2)
        print("Timeout waiting for receipt")
    else:
        print("Failed to submit UserOp")


def cmd_info(args):
    """Display account info and keypair details."""
    ecdsa_key = args.ecdsa_key.replace("0x", "")
    acct = Account.from_key(bytes.fromhex(ecdsa_key))
    print(f"ECDSA address: {acct.address}")

    keypair_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), f".sphincs_keypair_{args.variant}.json")
    if os.path.exists(keypair_file):
        with open(keypair_file) as f:
            kp = json.load(f)
        print(f"Variant: {kp['variant']}")
        print(f"pkSeed:  {kp['seed']}")
        print(f"pkRoot:  {kp['root']}")
        print(f"Factory: {kp['factory']}")
    else:
        print(f"No saved keypair for variant {args.variant}. Run 'create' first.")


# ============================================================
#  Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="SPHINCS+ 4337 UserOp Tool")
    sub = parser.add_subparsers(dest="command")

    # create
    p_create = sub.add_parser("create", help="Create a new SPHINCS+ account")
    p_create.add_argument("--factory", required=True, help="Factory contract address")
    p_create.add_argument("--ecdsa-key", required=True, help="ECDSA private key (hex)")
    p_create.add_argument("--variant", choices=["c2", "c3"], default="c2", help="SPHINCS+ variant")

    # send
    p_send = sub.add_parser("send", help="Send a UserOp")
    p_send.add_argument("--account", required=True, help="SphincsAccount address")
    p_send.add_argument("--ecdsa-key", required=True, help="ECDSA private key (hex)")
    p_send.add_argument("--to", required=True, help="Recipient address")
    p_send.add_argument("--value", default="0.001", help="Value in ETH")
    p_send.add_argument("--variant", choices=["c2", "c3"], default="c2", help="SPHINCS+ variant")

    # info
    p_info = sub.add_parser("info", help="Show account info")
    p_info.add_argument("--ecdsa-key", required=True, help="ECDSA private key (hex)")
    p_info.add_argument("--variant", choices=["c2", "c3"], default="c2", help="SPHINCS+ variant")

    args = parser.parse_args()

    if args.command == "create":
        cmd_create(args)
    elif args.command == "send":
        cmd_send(args)
    elif args.command == "info":
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
