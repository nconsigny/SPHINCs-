#!/usr/bin/env python3
"""
JARDÍN 4337 UserOp — deploy account, send Type 1 (C11 + register), send Type 2 (FORS+C compact).

Usage:
    python3 script/jardin_userop.py deploy     # Deploy JardinAccount, fund it
    python3 script/jardin_userop.py type1      # Send Type 1 UserOp (C11 + sub-key registration)
    python3 script/jardin_userop.py type2      # Send Type 2 UserOp (FORS+C compact)
    python3 script/jardin_userop.py both       # Deploy + Type1 + Type2 in sequence

Environment: PRIVATE_KEY, SEPOLIA_RPC_URL, PIMLICO_API_KEY (from .env)
"""

import sys
import os
import json
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import (
    sign_variant, sign_with_known_keys, derive_keys, keccak256, to_b32, N_MASK,
    _build_hypertree_d2, build_subtree_root, eprint, VARIANTS
)
from jardin_signer import (
    jardin_derive_keys, build_unbalanced_tree, jardin_grind_and_sign,
    get_unbalanced_auth_path, jardin_sentinel, N, K, A, A_MASK,
    th, make_adrs, th_pair, th_multi
)
from eth_abi import encode, decode
from eth_account import Account

# ============================================================
#  Constants
# ============================================================

ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
C11_VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
JARDIN_FACTORY = "0xa6A947A3A878EAF742179884c996cFE80cD8F5F9"
CHAIN_ID = 11155111

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardin_state.json")

# EIP-712 hashes
PACKED_USEROP_TYPEHASH = keccak256(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)"
).to_bytes(32, "big")

_EIP712_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)"
).to_bytes(32, "big")

def keccak_bytes(data: bytes) -> bytes:
    return keccak256(data).to_bytes(32, "big")

def _domain_separator():
    return keccak_bytes(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [_EIP712_DOMAIN_TYPEHASH,
         keccak_bytes(b"ERC4337"), keccak_bytes(b"1"),
         CHAIN_ID, bytes.fromhex(ENTRYPOINT_V09[2:])]
    ))

DOMAIN_SEP = _domain_separator()

# ============================================================
#  Env / Cast helpers
# ============================================================

def load_env():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    env = {}
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

def cast(*args, **kwargs):
    """Run a cast command, return stdout."""
    env = load_env()
    cmd = [os.path.expanduser("~/.foundry/bin/cast")] + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.get("timeout", 120),
                          env={**os.environ, **env})
    if proc.returncode != 0:
        eprint(f"  cast error: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip()

def cast_send(*args):
    env = load_env()
    cmd = [os.path.expanduser("~/.foundry/bin/cast"), "send"] + list(args) + [
        "--rpc-url", env["SEPOLIA_RPC_URL"], "--private-key", env["PRIVATE_KEY"]]
    eprint(f"  cast send {args[0][:10]}... {args[1] if len(args) > 1 else ''}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env={**os.environ, **env})
    if proc.returncode != 0:
        eprint(f"  FAILED: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip()

def to_hex(val, length=32):
    return "0x" + val.to_bytes(length, "big").hex()

# ============================================================
#  Key Generation
# ============================================================

def generate_master_c11_keys(entropy_int):
    """Generate C11 master SPHINCS+ keys: (pkSeed, skSeed, pkRoot)."""
    seed, sk_seed = derive_keys(entropy_int)
    cfg = VARIANTS["c11"]
    eprint("  Building C11 pkRoot (top-layer subtree)...")
    t0 = time.time()
    pk_root = _build_hypertree_d2(seed, sk_seed, cfg["subtree_h"], cfg)
    eprint(f"  C11 pkRoot done: {time.time()-t0:.1f}s")
    return seed, sk_seed, pk_root

def generate_sub_keys(master_sk_seed, q_max=32, slot_gen=1):
    """Generate JARDÍN sub-key from master secret. slot_gen differentiates key generations."""
    # Derive sub-key material from master
    sub_entropy = keccak256(to_b32(master_sk_seed) + b"jardin_device_" + str(slot_gen).encode())
    sub_pk_seed = keccak256(b"jardin_pk_seed" + to_b32(sub_entropy)) & N_MASK
    sub_sk_seed = keccak256(b"jardin_sk_seed" + to_b32(sub_entropy))

    eprint(f"  Building JARDÍN unbalanced tree (Q_MAX={q_max})...")
    fors_pks, spine, sent, sub_pk_root = build_unbalanced_tree(sub_pk_seed, sub_sk_seed, q_max)
    return sub_pk_seed, sub_sk_seed, sub_pk_root, fors_pks, spine, sent

# ============================================================
#  UserOp Construction
# ============================================================

def pack_user_op_hash(user_op):
    """Compute EIP-712 userOpHash."""
    init_code = bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b""
    call_data = bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b""
    pm_data = bytes.fromhex(user_op["paymasterAndData"][2:]) if user_op["paymasterAndData"] != "0x" else b""

    struct_hash = keccak_bytes(encode(
        ["bytes32", "address", "uint256", "bytes32", "bytes32",
         "bytes32", "uint256", "bytes32", "bytes32"],
        [PACKED_USEROP_TYPEHASH,
         bytes.fromhex(user_op["sender"][2:]),
         int(user_op["nonce"], 16),
         keccak_bytes(init_code), keccak_bytes(call_data),
         bytes.fromhex(user_op["accountGasLimits"][2:]),
         int(user_op["preVerificationGas"], 16),
         bytes.fromhex(user_op["gasFees"][2:]),
         keccak_bytes(pm_data)]
    ))
    return keccak_bytes(b"\x19\x01" + DOMAIN_SEP + struct_hash)

def build_execute_calldata(to_addr, value_wei, data=b""):
    selector = keccak_bytes(b"execute(address,uint256,bytes)")[:4]
    params = encode(
        ["address", "uint256", "bytes"],
        [bytes.fromhex(to_addr[2:]), value_wei, data]
    )
    return selector + params

def build_user_op(sender, nonce, call_data_hex, ver_gas=300000, call_gas=50000):
    """Build a PackedUserOperation dict."""
    env = load_env()
    rpc = env["SEPOLIA_RPC_URL"]

    max_priority = 2_000_000_000  # 2 gwei
    max_fee = 10_000_000_000      # 10 gwei

    account_gas_limits = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()
    gas_fees = "0x" + (max_priority.to_bytes(16, "big") + max_fee.to_bytes(16, "big")).hex()

    return {
        "sender": sender,
        "nonce": hex(nonce),
        "initCode": "0x",
        "callData": call_data_hex,
        "accountGasLimits": account_gas_limits,
        "preVerificationGas": hex(100_000),
        "gasFees": gas_fees,
        "paymasterAndData": "0x",
        "signature": "0x",
    }

def submit_handle_ops(user_op):
    """Submit UserOp via EntryPoint.handleOps using cast send."""
    env = load_env()
    from eth_account import Account
    deployer = Account.from_key(bytes.fromhex(env["PRIVATE_KEY"].replace("0x", "")))

    op_tuple = (
        bytes.fromhex(user_op["sender"][2:]),
        int(user_op["nonce"], 16),
        bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b"",
        bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b"",
        bytes.fromhex(user_op["accountGasLimits"][2:]),
        int(user_op["preVerificationGas"], 16),
        bytes.fromhex(user_op["gasFees"][2:]),
        bytes.fromhex(user_op["paymasterAndData"][2:]) if user_op["paymasterAndData"] != "0x" else b"",
        bytes.fromhex(user_op["signature"][2:]),
    )
    selector = keccak_bytes(
        b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)"
    )[:4]
    params = encode(
        ["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]", "address"],
        [[op_tuple], bytes.fromhex(deployer.address[2:])]
    )
    calldata = "0x" + (selector + params).hex()

    return cast_send(ENTRYPOINT_V09, calldata, "--gas-limit", "800000")

# ============================================================
#  Commands
# ============================================================

def cmd_deploy():
    """Deploy hybrid ECDSA + JARDÍN Account, fund it, save state."""
    eprint("=== Deploying Hybrid ECDSA + JARDÍN Account ===")

    env = load_env()
    ecdsa_key = env["PRIVATE_KEY"].replace("0x", "")
    ecdsa_acct = Account.from_key(bytes.fromhex(ecdsa_key))
    eprint(f"  ECDSA owner: {ecdsa_acct.address}")

    # Deterministic entropy from private key
    entropy = keccak256(bytes.fromhex(ecdsa_key) + b"jardin_master_v2")

    # Generate master C11 keys
    master_seed, master_sk, master_root = generate_master_c11_keys(entropy)
    eprint(f"  masterPkSeed: {to_hex(master_seed)[:18]}...")
    eprint(f"  masterPkRoot: {to_hex(master_root)[:18]}...")

    # Generate sub-keys
    sub_seed, sub_sk, sub_root, fors_pks, spine, sent = generate_sub_keys(master_sk, q_max=32)
    eprint(f"  subPkSeed: {to_hex(sub_seed)[:18]}...")
    eprint(f"  subPkRoot: {to_hex(sub_root)[:18]}...")

    # Deploy via factory (now takes ecdsaOwner)
    eprint("  Deploying account via factory...")
    result = cast_send(
        JARDIN_FACTORY,
        "createAccount(address,bytes32,bytes32)",
        ecdsa_acct.address, to_hex(master_seed), to_hex(master_root)
    )
    if not result:
        eprint("  Factory deploy failed!")
        sys.exit(1)

    for line in result.split("\n"):
        if "logs" in line.lower() or "topic" in line.lower():
            eprint(f"  {line}")

    # Compute counterfactual address
    eprint("  Computing account address...")
    addr_result = cast(
        "call", JARDIN_FACTORY,
        "getAddress(address,bytes32,bytes32)(address)",
        ecdsa_acct.address, to_hex(master_seed), to_hex(master_root),
        "--rpc-url", load_env()["SEPOLIA_RPC_URL"]
    )
    account_addr = addr_result.strip() if addr_result else None
    eprint(f"  Account: {account_addr}")

    if not account_addr:
        eprint("  Could not get account address!")
        sys.exit(1)

    # Fund account
    eprint("  Funding account with 0.005 ETH...")
    fund_result = cast_send(account_addr, "--value", "5000000000000000")  # 0.005 ETH
    if fund_result:
        eprint("  Funded!")
    else:
        eprint("  Funding may have failed, continuing...")

    # Random slot ID for sub-key registration
    r_slot = keccak256(to_b32(master_sk) + b"jardin_slot_r_1")

    # Save state
    state = {
        "account": account_addr,
        "master_seed": to_hex(master_seed),
        "master_root": to_hex(master_root),
        "master_entropy": to_hex(entropy),
        "sub_seed": to_hex(sub_seed),
        "sub_root": to_hex(sub_root),
        "r_slot": to_hex(r_slot),
        "q_max": 32,
        "next_q": 1,
        "slot_gen": 1,
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    eprint(f"  State saved to {STATE_FILE}")
    print(f"JARDÍN Account: {account_addr}")
    return state


def cmd_type1():
    """Send Type 1 UserOp: C11 stateless + sub-key registration.
    If the FORS+C tree is exhausted (next_q > q_max), generate a fresh sub-key."""
    eprint("=== Type 1 UserOp (ECDSA + C11 + Register Sub-Key) ===")

    with open(STATE_FILE) as f:
        state = json.load(f)

    env = load_env()
    account = state["account"]
    master_seed = int(state["master_seed"], 16)
    master_root = int(state["master_root"], 16)
    entropy = int(state["master_entropy"], 16)

    # Rederive master sk_seed
    _, master_sk = derive_keys(entropy)

    # Check if we need a fresh sub-key (tree exhausted or first registration)
    slot_gen = state.get("slot_gen", 1)
    if state.get("next_q", 1) > state.get("q_max", 32):
        slot_gen += 1
        eprint(f"  FORS+C tree exhausted — generating fresh sub-key (gen={slot_gen})...")
        sub_seed, sub_sk, sub_root, _, _, _ = generate_sub_keys(master_sk, q_max=32, slot_gen=slot_gen)
        r_slot = keccak256(to_b32(master_sk) + b"jardin_slot_r_" + str(slot_gen).encode())
        state["sub_seed"] = to_hex(sub_seed)
        state["sub_root"] = to_hex(sub_root)
        state["r_slot"] = to_hex(r_slot)
        state["next_q"] = 1
        state["slot_gen"] = slot_gen
        state["q_max"] = 32
        eprint(f"  New subPkRoot: {to_hex(sub_root)[:18]}...")
    else:
        eprint(f"  Using existing sub-key (gen={slot_gen})")

    sub_seed_int = int(state["sub_seed"], 16)
    sub_root_int = int(state["sub_root"], 16)
    r_slot = int(state["r_slot"], 16)

    # Get nonce
    nonce_hex = cast(
        "call", ENTRYPOINT_V09,
        "getNonce(address,uint192)(uint256)",
        account, "0",
        "--rpc-url", env["SEPOLIA_RPC_URL"]
    )
    nonce = int(nonce_hex.strip(), 10) if nonce_hex and not nonce_hex.startswith("0x") else int(nonce_hex.strip(), 16) if nonce_hex else 0
    eprint(f"  Nonce: {nonce}")

    # Build UserOp: send 0 ETH to self (noop, just for registration)
    call_data = build_execute_calldata(account, 0)
    user_op = build_user_op(account, nonce, "0x" + call_data.hex(), ver_gas=250_000)

    # Compute userOpHash
    user_op_hash = pack_user_op_hash(user_op)
    user_op_hash_int = int.from_bytes(user_op_hash, "big")
    eprint(f"  UserOp hash: 0x{user_op_hash.hex()[:16]}...")

    # Sign with C11
    eprint("  Signing with C11 (stateless)...")
    c11_sig_bytes = sign_with_known_keys("c11", user_op_hash_int, master_seed, master_sk, master_root)
    eprint(f"  C11 sig: {len(c11_sig_bytes)} bytes")

    # ECDSA sign the userOpHash
    env = load_env()
    ecdsa_key = env["PRIVATE_KEY"].replace("0x", "")
    ecdsa_acct = Account.from_key(bytes.fromhex(ecdsa_key))
    signed = ecdsa_acct.unsafe_sign_hash(user_op_hash)
    ecdsa_sig = (signed.r.to_bytes(32, "big") +
                 signed.s.to_bytes(32, "big") +
                 signed.v.to_bytes(1, "big"))
    eprint(f"  ECDSA sig: {len(ecdsa_sig)} bytes (owner={ecdsa_acct.address})")

    # Pack Type 1 signature: [0x01][ecdsaSig 65B][r 32B][subPkSeed 16B][subPkRoot 16B][c11_sig]
    sub_seed_bytes = (sub_seed_int >> 128).to_bytes(16, "big")
    sub_root_bytes = (sub_root_int >> 128).to_bytes(16, "big")
    type1_sig = bytes([0x01])
    type1_sig += ecdsa_sig
    type1_sig += r_slot.to_bytes(32, "big")
    type1_sig += sub_seed_bytes
    type1_sig += sub_root_bytes
    type1_sig += c11_sig_bytes

    eprint(f"  Type 1 sig total: {len(type1_sig)} bytes (ECDSA + C11)")
    user_op["signature"] = "0x" + type1_sig.hex()

    # Submit
    eprint("  Submitting handleOps...")
    result = submit_handle_ops(user_op)
    if result:
        for line in result.split("\n"):
            if "gasUsed" in line or "transactionHash" in line or "status" in line:
                eprint(f"  {line.strip()}")
                if "transactionHash" in line:
                    print(f"Type 1 tx: {line.split()[-1]}")
                if "gasUsed" in line:
                    print(f"Type 1 gas: {line.split()[-1]}")
        eprint("  Type 1 UserOp submitted!")
        # Save updated state (new sub-key if regenerated)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    else:
        eprint("  Type 1 failed!")
        sys.exit(1)


def cmd_type2():
    """Send Type 2 UserOp: FORS+C compact."""
    eprint("=== Type 2 UserOp (FORS+C Compact) ===")

    with open(STATE_FILE) as f:
        state = json.load(f)

    env = load_env()
    account = state["account"]
    sub_seed_int = int(state["sub_seed"], 16)
    sub_root_int = int(state["sub_root"], 16)
    r_slot = int(state["r_slot"], 16)
    q_max = state["q_max"]
    q_leaf = state.get("next_q", 1)
    slot_gen = state.get("slot_gen", 1)

    if q_leaf > q_max:
        eprint(f"  FORS+C tree exhausted (q={q_leaf} > q_max={q_max}). Run type1 to re-register.")
        sys.exit(1)

    # Rederive sub sk_seed using the correct slot_gen
    master_entropy = int(state["master_entropy"], 16)
    _, master_sk = derive_keys(master_entropy)
    sub_entropy = keccak256(to_b32(master_sk) + b"jardin_device_" + str(slot_gen).encode())
    sub_sk_seed = keccak256(b"jardin_sk_seed" + to_b32(sub_entropy))

    # Rebuild unbalanced tree (needed for auth path)
    eprint(f"  Rebuilding unbalanced tree (q_max={q_max})...")
    sub_pk_seed = sub_seed_int
    fors_pks, spine, sent, sub_pk_root = build_unbalanced_tree(sub_pk_seed, sub_sk_seed, q_max)
    assert sub_pk_root == sub_root_int, "Sub-key root mismatch!"

    # Get nonce
    nonce_hex = cast(
        "call", ENTRYPOINT_V09,
        "getNonce(address,uint192)(uint256)",
        account, "0",
        "--rpc-url", env["SEPOLIA_RPC_URL"]
    )
    nonce = int(nonce_hex.strip(), 10) if nonce_hex and not nonce_hex.startswith("0x") else int(nonce_hex.strip(), 16) if nonce_hex else 0
    eprint(f"  Nonce: {nonce}")

    # Build UserOp: send 0 ETH to self
    call_data = build_execute_calldata(account, 0)
    user_op = build_user_op(account, nonce, "0x" + call_data.hex(), ver_gas=200_000)

    # Compute userOpHash
    user_op_hash = pack_user_op_hash(user_op)
    user_op_hash_int = int.from_bytes(user_op_hash, "big")
    eprint(f"  UserOp hash: 0x{user_op_hash.hex()[:16]}...")

    # Sign with FORS+C
    eprint(f"  Signing with FORS+C (q={q_leaf})...")
    fors_sig, R, counter, digest = jardin_grind_and_sign(
        sub_pk_seed, sub_sk_seed, sub_pk_root, user_op_hash_int, q_leaf)
    unb_auth = get_unbalanced_auth_path(fors_pks, spine, sent, q_leaf, q_max)

    # Full FORS+C sig
    forsc_sig = fors_sig
    for node in unb_auth:
        forsc_sig += to_b32(node)[:N]
    eprint(f"  FORS+C sig: {len(forsc_sig)} bytes")

    # ECDSA sign the userOpHash
    env_data = load_env()
    ecdsa_key = env_data["PRIVATE_KEY"].replace("0x", "")
    ecdsa_acct = Account.from_key(bytes.fromhex(ecdsa_key))
    signed = ecdsa_acct.unsafe_sign_hash(user_op_hash)
    ecdsa_sig = (signed.r.to_bytes(32, "big") +
                 signed.s.to_bytes(32, "big") +
                 signed.v.to_bytes(1, "big"))
    eprint(f"  ECDSA sig: {len(ecdsa_sig)} bytes (owner={ecdsa_acct.address})")

    # Pack Type 2 signature: [0x02][ecdsaSig 65B][H(r) 32B][subPkSeed 16B][subPkRoot 16B][forsc_sig]
    h_r = keccak256(r_slot.to_bytes(32, "big")).to_bytes(32, "big")
    sub_seed_bytes = (sub_seed_int >> 128).to_bytes(16, "big")
    sub_root_bytes = (sub_root_int >> 128).to_bytes(16, "big")

    type2_sig = bytes([0x02])
    type2_sig += ecdsa_sig
    type2_sig += h_r
    type2_sig += sub_seed_bytes
    type2_sig += sub_root_bytes
    type2_sig += forsc_sig

    eprint(f"  Type 2 sig total: {len(type2_sig)} bytes (ECDSA + FORS+C)")
    user_op["signature"] = "0x" + type2_sig.hex()

    # Submit
    eprint("  Submitting handleOps...")
    result = submit_handle_ops(user_op)
    if result:
        for line in result.split("\n"):
            if "gasUsed" in line or "transactionHash" in line or "status" in line:
                eprint(f"  {line.strip()}")
                if "transactionHash" in line:
                    print(f"Type 2 tx: {line.split()[-1]}")
                if "gasUsed" in line:
                    print(f"Type 2 gas: {line.split()[-1]}")
        eprint("  Type 2 UserOp submitted!")

        # Update next_q
        state["next_q"] = q_leaf + 1
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    else:
        eprint("  Type 2 failed!")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jardin_userop.py [deploy|type1|type2|both]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "deploy":
        cmd_deploy()
    elif cmd == "type1":
        cmd_type1()
    elif cmd == "type2":
        cmd_type2()
    elif cmd == "both":
        state = cmd_deploy()
        time.sleep(5)  # Wait for deployment to confirm
        cmd_type1()
        time.sleep(5)  # Wait for Type 1 to confirm (slot registration)
        cmd_type2()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
