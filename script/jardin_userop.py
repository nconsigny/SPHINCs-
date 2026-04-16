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
    jardin_derive_keys, build_balanced_tree, jardin_sign, Q_MAX,
    N, K, A, A_MASK, th, make_adrs, th_pair, th_multi
)
from eth_abi import encode, decode
from eth_account import Account

# ============================================================
#  Constants
# ============================================================

ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
C11_VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
FORSC_VERIFIER = "0xef0f8def0caef9863b4061d6f2397d7d57c9bdfc"
JARDIN_FACTORY = "0x9ff19a7d8e438b59f1f0f892caa004784f491e65"
CHAIN_ID = 11155111
BUNDLER_URL = "https://api.candide.dev/public/v3/11155111"

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

def generate_sub_keys(master_sk_seed, slot_gen=1):
    """Generate JARDÍN sub-key from master secret. slot_gen differentiates key generations."""
    # Derive sub-key material from master
    sub_entropy = keccak256(to_b32(master_sk_seed) + b"jardin_device_" + str(slot_gen).encode())
    sub_pk_seed = keccak256(b"jardin_pk_seed" + to_b32(sub_entropy)) & N_MASK
    sub_sk_seed = keccak256(b"jardin_sk_seed" + to_b32(sub_entropy))

    eprint(f"  Building JARDÍN balanced tree (Q_MAX={Q_MAX})...")
    levels, sub_pk_root = build_balanced_tree(sub_pk_seed, sub_sk_seed)
    return sub_pk_seed, sub_sk_seed, sub_pk_root, levels

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
    entropy = keccak256(bytes.fromhex(ecdsa_key) + b"jardin_master_v6_h7")

    # Generate master C11 keys
    master_seed, master_sk, master_root = generate_master_c11_keys(entropy)
    eprint(f"  masterPkSeed: {to_hex(master_seed)[:18]}...")
    eprint(f"  masterPkRoot: {to_hex(master_root)[:18]}...")

    # Generate sub-keys
    sub_seed, sub_sk, sub_root, _levels = generate_sub_keys(master_sk)
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

    # Save state
    state = {
        "account": account_addr,
        "master_seed": to_hex(master_seed),
        "master_root": to_hex(master_root),
        "master_entropy": to_hex(entropy),
        "sub_seed": to_hex(sub_seed),
        "sub_root": to_hex(sub_root),
        "q_max": Q_MAX,
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
    if state.get("next_q", 1) > state.get("q_max", Q_MAX):
        slot_gen += 1
        eprint(f"  FORS+C tree exhausted — generating fresh sub-key (gen={slot_gen})...")
        sub_seed, sub_sk, sub_root, _levels = generate_sub_keys(master_sk, slot_gen=slot_gen)
        state["sub_seed"] = to_hex(sub_seed)
        state["sub_root"] = to_hex(sub_root)
        state["next_q"] = 1
        state["slot_gen"] = slot_gen
        state["q_max"] = Q_MAX
        eprint(f"  New subPkRoot: {to_hex(sub_root)[:18]}...")
    else:
        eprint(f"  Using existing sub-key (gen={slot_gen})")

    sub_seed_int = int(state["sub_seed"], 16)
    sub_root_int = int(state["sub_root"], 16)

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

    # Pack Type 1 signature: [0x01][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][c11_sig]
    sub_seed_bytes = (sub_seed_int >> 128).to_bytes(16, "big")
    sub_root_bytes = (sub_root_int >> 128).to_bytes(16, "big")
    type1_sig = bytes([0x01])
    type1_sig += ecdsa_sig
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

    # Rebuild balanced tree (needed for auth path)
    eprint(f"  Rebuilding balanced tree (Q_MAX={Q_MAX})...")
    sub_pk_seed = sub_seed_int
    levels, sub_pk_root = build_balanced_tree(sub_pk_seed, sub_sk_seed)
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
    forsc_sig, R, counter, digest = jardin_sign(
        sub_pk_seed, sub_sk_seed, sub_pk_root, levels, user_op_hash_int, q_leaf)
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

    # Pack Type 2 signature: [0x02][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][forsc_sig]
    sub_seed_bytes = (sub_seed_int >> 128).to_bytes(16, "big")
    sub_root_bytes = (sub_root_int >> 128).to_bytes(16, "big")

    type2_sig = bytes([0x02])
    type2_sig += ecdsa_sig
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


def _bundler_rpc(method, params):
    import requests
    r = requests.post(BUNDLER_URL, json={
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }, timeout=60)
    return r.json()

def submit_via_bundler(uop):
    """Submit a UserOp via the Candide bundler (eth_sendUserOperation),
    then poll eth_getUserOperationReceipt for confirmation.
    Returns (ok: bool, actualGasCost_wei: int, tx_hash: str|None)."""
    # EntryPoint 0.9 uses a flat PackedUserOperation format; bundler expects
    # the standard v0.7-style fields expanded. Convert.
    vg = int(uop["accountGasLimits"][2:][:32], 16)
    cg = int(uop["accountGasLimits"][2:][32:], 16)
    mpfpg = int(uop["gasFees"][2:][:32], 16)
    mfpg = int(uop["gasFees"][2:][32:], 16)
    payload = {
        "sender": uop["sender"],
        "nonce": uop["nonce"],
        "callData": uop["callData"],
        "callGasLimit": hex(cg),
        "verificationGasLimit": hex(vg),
        "preVerificationGas": uop["preVerificationGas"],
        "maxPriorityFeePerGas": hex(mpfpg),
        "maxFeePerGas": hex(mfpg),
        "signature": uop["signature"],
    }
    if uop.get("initCode", "0x") != "0x":
        payload["factory"] = "0x" + uop["initCode"][2:][:40]
        payload["factoryData"] = "0x" + uop["initCode"][2:][40:]
    if uop.get("paymasterAndData", "0x") != "0x":
        payload["paymaster"] = "0x" + uop["paymasterAndData"][2:][:40]
    resp = _bundler_rpc("eth_sendUserOperation", [payload, ENTRYPOINT_V09])
    if "error" in resp:
        eprint(f"  bundler error: {resp['error'].get('message','?')[:200]}")
        return False, 0, None
    uop_hash = resp.get("result")
    if not uop_hash:
        return False, 0, None
    # Poll the receipt (up to ~60s)
    import time as _time
    for _ in range(30):
        _time.sleep(2)
        r = _bundler_rpc("eth_getUserOperationReceipt", [uop_hash])
        rec = r.get("result")
        if rec:
            success = rec.get("success", False)
            actual_cost = int(rec.get("actualGasCost", "0x0"), 16)
            tx_hash = rec.get("receipt", {}).get("transactionHash")
            return bool(success), actual_cost, tx_hash
    return False, 0, None


def cmd_cycle():
    """Full slot lifecycle on Sepolia 4337 — builds each tree once and reuses
    it across all Q_MAX compact signatures. Respects the state file's current
    slot_gen and next_q, so it can resume after a partial run."""
    from jardin_signer import jardin_sign

    eprint(f"=== Full 4337 cycle ===")

    with open(STATE_FILE) as f:
        state = json.load(f)

    env = load_env()
    account = state["account"]
    master_seed_int = int(state["master_seed"], 16)
    master_root_int = int(state["master_root"], 16)
    master_entropy = int(state["master_entropy"], 16)
    _, master_sk = derive_keys(master_entropy)

    ecdsa_key = env["PRIVATE_KEY"].replace("0x", "")
    ecdsa_acct = Account.from_key(bytes.fromhex(ecdsa_key))
    gas_log = []

    SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def _ecdsa_sign(h):
        s = ecdsa_acct.unsafe_sign_hash(h)
        r_val, s_val, v = s.r, s.s, s.v
        # Canonicalize to low-s form (OpenZeppelin ECDSA rejects s > N/2).
        if s_val > SECP256K1_N // 2:
            s_val = SECP256K1_N - s_val
            v = 28 if v == 27 else 27
        return (r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big") +
                v.to_bytes(1, "big"))

    # Seed the UserOp nonce from on-chain once, then track locally —
    # Ankr's load-balanced RPC sometimes returns stale reads right after
    # a confirmed tx, which causes nonce collisions ("AA25").
    _h = cast("call", ENTRYPOINT_V09, "getNonce(address,uint192)(uint256)",
              account, "0", "--rpc-url", env["SEPOLIA_RPC_URL"])
    _uop_nonce = [int(_h.strip(), 10) if _h and not _h.strip().startswith("0x")
                  else int(_h.strip(), 16) if _h else 0]
    eprint(f"  Initial UserOp nonce: {_uop_nonce[0]}")

    def _nonce():
        return _uop_nonce[0]

    def _advance_nonce():
        _uop_nonce[0] += 1

    def _run(label, sig_bytes, ver_gas):
        call_data = build_execute_calldata(account, 0)
        uop = build_user_op(account, _nonce(), "0x" + call_data.hex(), ver_gas=ver_gas)
        uop["signature"] = "0x" + sig_bytes.hex()
        result = submit_handle_ops(uop)
        gas = 0
        status = ""
        if result:
            for line in result.split("\n"):
                if "gasUsed" in line: gas = int(line.split()[-1])
                if line.strip().startswith("status") and "(" in line:
                    status = line.split()[-1].strip("()")
        ok = status == "success"
        marker = "OK" if ok else "FAIL"
        print(f"  {label:40s} gas={gas:>7} {marker}", flush=True)
        gas_log.append({"label": label, "gas": gas, "ok": ok})
        return ok

    def _build_uop_hash(ver_gas):
        call_data = build_execute_calldata(account, 0)
        uop = build_user_op(account, _nonce(), "0x" + call_data.hex(), ver_gas=ver_gas)
        h = pack_user_op_hash(uop)
        return uop, h

    def _type1(label, ss_b, sr_b, ver_gas=250_000):
        uop, h = _build_uop_hash(ver_gas)
        ecdsa = _ecdsa_sign(h)
        c11 = sign_with_known_keys("c11", int.from_bytes(h, "big"),
                                    master_seed_int, master_sk, master_root_int)
        sig = bytes([0x01]) + ecdsa + ss_b + sr_b + c11
        uop["signature"] = "0x" + sig.hex()
        ok, cost, tx_hash = submit_via_bundler(uop)
        if ok: _advance_nonce()
        print(f"  {label:40s} cost={cost:>15} wei  {'OK' if ok else 'FAIL'}"
              + (f"  tx={tx_hash[:18]}..." if tx_hash else ""), flush=True)
        gas_log.append({"label": label, "cost": cost, "ok": ok, "tx": tx_hash})
        return ok

    def _type2(q, sub_seed, sub_sk, sub_root, levels, ss_b, sr_b, ver_gas=220_000):
        uop, h = _build_uop_hash(ver_gas)
        ecdsa = _ecdsa_sign(h)
        forsc, _, _, _ = jardin_sign(sub_seed, sub_sk, sub_root, levels,
                                      int.from_bytes(h, "big"), q)
        sig = bytes([0x02]) + ecdsa + ss_b + sr_b + forsc
        uop["signature"] = "0x" + sig.hex()
        ok, cost, tx_hash = submit_via_bundler(uop)
        if ok: _advance_nonce()
        label = f"Type2 q={q} (slot {state.get('slot_gen', 1)})"
        print(f"  {label:40s} cost={cost:>15} wei  {'OK' if ok else 'FAIL'}"
              + (f"  tx={tx_hash[:18]}..." if tx_hash else ""), flush=True)
        gas_log.append({"label": label, "cost": cost, "ok": ok, "tx": tx_hash})
        return ok

    # ─── Finish current slot ──────────────────────────────────────────
    slot_gen = state.get("slot_gen", 1)
    next_q = state.get("next_q", 1)
    sub_seed = int(state["sub_seed"], 16)
    sub_root = int(state["sub_root"], 16)
    eprint(f"\n[SLOT {slot_gen}] Resuming — rebuilding tree (q={next_q}..{Q_MAX})...")

    sub_ent = keccak256(to_b32(master_sk) + b"jardin_device_" + str(slot_gen).encode())
    sub_sk = keccak256(b"jardin_sk_seed" + to_b32(sub_ent))
    t0 = time.time()
    from jardin_signer import build_balanced_tree
    levels, rebuilt = build_balanced_tree(sub_seed, sub_sk)
    eprint(f"  Keygen: {time.time()-t0:.1f}s  (root match: {rebuilt == sub_root})")
    ss_b = (sub_seed >> 128).to_bytes(16, "big")
    sr_b = (sub_root >> 128).to_bytes(16, "big")

    for q in range(next_q, Q_MAX + 1):
        _type2(q, sub_seed, sub_sk, sub_root, levels, ss_b, sr_b)
        state["next_q"] = q + 1
        with open(STATE_FILE, "w") as f: json.dump(state, f, indent=2)

    # ─── Re-register to slot_gen+1, then one compact tx ───────────────
    slot_gen += 1
    eprint(f"\n[SLOT {slot_gen}] Fresh sub-key + tree...")
    sub_seed, sub_sk, sub_root, levels = generate_sub_keys(master_sk, slot_gen=slot_gen)
    ss_b = (sub_seed >> 128).to_bytes(16, "big")
    sr_b = (sub_root >> 128).to_bytes(16, "big")
    state["sub_seed"] = to_hex(sub_seed)
    state["sub_root"] = to_hex(sub_root)
    state["slot_gen"] = slot_gen
    state["next_q"] = 1
    with open(STATE_FILE, "w") as f: json.dump(state, f, indent=2)

    _type1(f"Type1 re-register (slot {slot_gen})", ss_b, sr_b)
    state["next_q"] = 2
    _type2(1, sub_seed, sub_sk, sub_root, levels, ss_b, sr_b)
    with open(STATE_FILE, "w") as f: json.dump(state, f, indent=2)

    # ─── Summary ──────────────────────────────────────────────────────
    ok = sum(1 for g in gas_log if g["ok"])
    fail = len(gas_log) - ok
    print(f"\n{'='*50}\nTotal: {len(gas_log)}  Success: {ok}  Failed: {fail}")
    t1 = [g["cost"] for g in gas_log if "Type1" in g["label"] and g["ok"]]
    t2 = [g["cost"] for g in gas_log if "Type2" in g["label"] and g["ok"]]
    if t1: print(f"Type 1 actualGasCost: min={min(t1)} max={max(t1)} avg={sum(t1)//len(t1)} wei")
    if t2: print(f"Type 2 actualGasCost: min={min(t2)} max={max(t2)} avg={sum(t2)//len(t2)} wei")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jardin_userop.py [deploy|type1|type2|both|cycle]")
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
    elif cmd == "cycle":
        # Full slot lifecycle: Type1 register → Q_MAX × Type2 → Type1 re-register → Type2
        cmd_cycle()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
