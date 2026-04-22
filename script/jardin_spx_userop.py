#!/usr/bin/env python3
"""
JARDÍN SPX 4337 UserOp — deploy account, send Type 1 (SPX + register),
send Type 2 (FORS+C compact). Uses the Candide bundler for submission.

Usage:
    python3 script/jardin_spx_userop.py deploy
    python3 script/jardin_spx_userop.py cycle        # deploy + 3×type1 + 3×type2
    python3 script/jardin_spx_userop.py save-addresses <spx> <forsc> <factory>

Environment (read from .env):
    PRIVATE_KEY            — deployer / ECDSA owner
    SEPOLIA_RPC_URL        — RPC endpoint

Addresses (.jardin_spx_addresses.json):
    spxVerifier, forscVerifier, factory
"""

import sys, os, json, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_abi import encode
from eth_account import Account
from jardin_spx_signer import (
    derive_spx_keys as spx_derive,
    build_pk_root as spx_build_root,
    spx_sign,
    keccak256 as _keccak_bytes,   # returns bytes
    N as SPX_N,
)
from jardin_signer import (
    build_balanced_tree,
    jardin_sign,
    Q_MAX,
)

# ============================================================
#  Constants
# ============================================================

ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111
BUNDLER_URL_TEMPLATE = "https://api.candide.dev/public/v3/{chain}"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(PROJECT_ROOT, "script", ".jardin_spx_state.json")
ADDR_FILE  = os.path.join(PROJECT_ROOT, "script", ".jardin_spx_addresses.json")
ENV_FILE   = os.path.join(PROJECT_ROOT, ".env")

# ============================================================
#  Env + cast
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

def load_addresses():
    if not os.path.exists(ADDR_FILE):
        eprint(f"Missing {ADDR_FILE}. Run `save-addresses <spx> <forsc> <factory>` first.")
        sys.exit(1)
    with open(ADDR_FILE) as f:
        return json.load(f)

def save_addresses(spx, forsc, factory):
    with open(ADDR_FILE, "w") as f:
        json.dump({"spxVerifier": spx, "forscVerifier": forsc, "factory": factory}, f, indent=2)
    eprint(f"  addresses → {ADDR_FILE}")

def cast(*args, **kwargs):
    env = load_env()
    cmd = [os.path.expanduser("~/.foundry/bin/cast")] + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=kwargs.get("timeout", 120),
                          env={**os.environ, **env})
    if proc.returncode != 0:
        eprint(f"  cast error: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip()

def cast_send(*args):
    env = load_env()
    cmd = [os.path.expanduser("~/.foundry/bin/cast"), "send"] + list(args) + [
        "--rpc-url", env["SEPOLIA_RPC_URL"],
        "--private-key", env["PRIVATE_KEY"]]
    eprint(f"  cast send {args[0][:18]}... {args[1] if len(args) > 1 else ''}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env={**os.environ, **env})
    if proc.returncode != 0:
        eprint(f"  FAILED: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip()

def b16_to_bytes32_hex(b16: bytes) -> str:
    """Return 0x<hex16><32 zero hex> so cast sees a 32-byte word with value in high 16 bytes."""
    assert len(b16) == 16, f"expected 16B, got {len(b16)}"
    return "0x" + b16.hex() + "00" * 16

# ============================================================
#  EIP-712 userOpHash
# ============================================================

def keccak_bytes(data: bytes) -> bytes:
    return _keccak_bytes(data)

PACKED_USEROP_TYPEHASH = keccak_bytes(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)"
)

_EIP712_DOMAIN_TYPEHASH = keccak_bytes(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)"
)

def _domain_separator():
    return keccak_bytes(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [_EIP712_DOMAIN_TYPEHASH,
         keccak_bytes(b"ERC4337"), keccak_bytes(b"1"),
         CHAIN_ID, bytes.fromhex(ENTRYPOINT_V09[2:])]))

DOMAIN_SEP = _domain_separator()

def pack_user_op_hash(uop):
    init_code = bytes.fromhex(uop["initCode"][2:]) if uop["initCode"] != "0x" else b""
    call_data = bytes.fromhex(uop["callData"][2:]) if uop["callData"] != "0x" else b""
    pm_data   = bytes.fromhex(uop["paymasterAndData"][2:]) if uop["paymasterAndData"] != "0x" else b""
    struct_hash = keccak_bytes(encode(
        ["bytes32", "address", "uint256", "bytes32", "bytes32",
         "bytes32", "uint256", "bytes32", "bytes32"],
        [PACKED_USEROP_TYPEHASH,
         bytes.fromhex(uop["sender"][2:]),
         int(uop["nonce"], 16),
         keccak_bytes(init_code), keccak_bytes(call_data),
         bytes.fromhex(uop["accountGasLimits"][2:]),
         int(uop["preVerificationGas"], 16),
         bytes.fromhex(uop["gasFees"][2:]),
         keccak_bytes(pm_data)]))
    return keccak_bytes(b"\x19\x01" + DOMAIN_SEP + struct_hash)

def build_execute_calldata(to_addr, value_wei, data=b""):
    selector = keccak_bytes(b"execute(address,uint256,bytes)")[:4]
    params = encode(["address", "uint256", "bytes"],
                    [bytes.fromhex(to_addr[2:]), value_wei, data])
    return selector + params

def build_user_op(sender, nonce, call_data_hex, ver_gas=500_000, call_gas=50_000, pvg=200_000):
    max_priority = 1_500_000_000
    max_fee      = 3_000_000_000
    gas_limits = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()
    gas_fees   = "0x" + (max_priority.to_bytes(16, "big") + max_fee.to_bytes(16, "big")).hex()
    return {
        "sender": sender, "nonce": hex(nonce),
        "initCode": "0x", "callData": call_data_hex,
        "accountGasLimits": gas_limits,
        "preVerificationGas": hex(pvg),
        "gasFees": gas_fees, "paymasterAndData": "0x", "signature": "0x",
    }

# ============================================================
#  Candide bundler
# ============================================================

def bundler_url():
    return BUNDLER_URL_TEMPLATE.format(chain=CHAIN_ID)

def bundler_rpc(method, params):
    import requests
    r = requests.post(bundler_url(), json={
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }, timeout=60)
    return r.json()

def submit_via_bundler(uop, wait_timeout=90):
    vg = int(uop["accountGasLimits"][2:][:32], 16)
    cg = int(uop["accountGasLimits"][2:][32:], 16)
    mpfpg = int(uop["gasFees"][2:][:32], 16)
    mfpg  = int(uop["gasFees"][2:][32:], 16)
    payload = {
        "sender": uop["sender"], "nonce": uop["nonce"],
        "callData": uop["callData"],
        "callGasLimit": hex(cg),
        "verificationGasLimit": hex(vg),
        "preVerificationGas": uop["preVerificationGas"],
        "maxPriorityFeePerGas": hex(mpfpg),
        "maxFeePerGas": hex(mfpg),
        "signature": uop["signature"],
    }
    if uop.get("initCode", "0x") != "0x":
        payload["factory"]     = "0x" + uop["initCode"][2:][:40]
        payload["factoryData"] = "0x" + uop["initCode"][2:][40:]
    if uop.get("paymasterAndData", "0x") != "0x":
        payload["paymaster"] = "0x" + uop["paymasterAndData"][2:][:40]

    resp = bundler_rpc("eth_sendUserOperation", [payload, ENTRYPOINT_V09])
    if "error" in resp:
        msg = str(resp["error"].get("message", "?"))[:300]
        eprint(f"  bundler error: {msg}")
        return False, 0, None
    uop_hash = resp.get("result")
    if not uop_hash:
        return False, 0, None
    for _ in range(wait_timeout // 3):
        time.sleep(3)
        r = bundler_rpc("eth_getUserOperationReceipt", [uop_hash])
        rec = r.get("result")
        if rec:
            ok = bool(rec.get("success", False))
            cost = int(rec.get("actualGasCost", "0x0"), 16)
            tx_hash = (rec.get("receipt") or {}).get("transactionHash")
            return ok, cost, tx_hash
    eprint(f"  bundler timeout; uop_hash={uop_hash}")
    return False, 0, None

# ============================================================
#  ECDSA
# ============================================================

SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def ecdsa_sign(ecdsa_acct, h):
    s = ecdsa_acct.unsafe_sign_hash(h)
    r_val, s_val, v = s.r, s.s, s.v
    if s_val > SECP256K1_N // 2:
        s_val = SECP256K1_N - s_val
        v = 28 if v == 27 else 27
    return r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big") + v.to_bytes(1, "big")

# ============================================================
#  Key derivation wrappers
# ============================================================

def master_sk_from_env():
    env = load_env()
    deterministic = keccak_bytes(
        bytes.fromhex(env["PRIVATE_KEY"].replace("0x", "")) + b"jardin_spx_master_v1"
    )
    return deterministic  # 32 bytes

def gen_spx_keys():
    master = master_sk_from_env()
    sk_seed, sk_prf, pk_seed = spx_derive(master)
    eprint("  Building SPX top-layer XMSS root (16 WOTS+ keypairs)...")
    pk_root = spx_build_root(pk_seed, sk_seed)
    return sk_seed, sk_prf, pk_seed, pk_root

def gen_sub_keys(slot_gen, h=7):
    """Derive a FORS+C sub-key from master + slot_gen, build its balanced tree.
       jardin_signer expects ints (not bytes). Convert consistently."""
    master = master_sk_from_env()
    tag = b"jardin_spx_sub_" + str(slot_gen).encode()
    if h is not None:
        tag += b"_h" + str(h).encode()
    sub_entropy = keccak_bytes(master + tag)
    # jardin_signer uses ints in high bytes (N_MASK masked)
    N_MASK_INT = (1 << 256) - (1 << 128)
    sub_pk_seed = int.from_bytes(keccak_bytes(b"jardin_spx_pk_seed" + sub_entropy), "big") & N_MASK_INT
    sub_sk_seed = int.from_bytes(keccak_bytes(b"jardin_spx_sk_seed" + sub_entropy), "big")
    q_max = 1 << h
    eprint(f"  Building FORS+C balanced tree (slot_gen={slot_gen}, h={h}, Q_MAX={q_max})...")
    levels, sub_pk_root = build_balanced_tree(sub_pk_seed, sub_sk_seed, h)
    return sub_pk_seed, sub_sk_seed, sub_pk_root, levels

def int_to_b16_high(v: int) -> bytes:
    """FORS+C int representation (value in high 16B of a 32B word) → raw 16B."""
    return (v >> 128).to_bytes(16, "big")

# ============================================================
#  Commands
# ============================================================

def cmd_deploy():
    eprint("=== Deploying JARDÍN SPX Account ===")
    addr = load_addresses()
    factory = addr["factory"]
    env = load_env()
    ecdsa = Account.from_key(bytes.fromhex(env["PRIVATE_KEY"].replace("0x", "")))
    eprint(f"  ECDSA owner: {ecdsa.address}")

    _, _, spx_pk_seed, spx_pk_root = gen_spx_keys()
    spx_pk_seed_hex = b16_to_bytes32_hex(spx_pk_seed)
    spx_pk_root_hex = b16_to_bytes32_hex(spx_pk_root)
    eprint(f"  spxPkSeed: {spx_pk_seed.hex()}")
    eprint(f"  spxPkRoot: {spx_pk_root.hex()}")

    eprint("  cast send factory.createAccount...")
    cast_send(factory, "createAccount(address,bytes32,bytes32)",
              ecdsa.address, spx_pk_seed_hex, spx_pk_root_hex)

    account_addr = cast(
        "call", factory,
        "getAddress(address,bytes32,bytes32)(address)",
        ecdsa.address, spx_pk_seed_hex, spx_pk_root_hex,
        "--rpc-url", env["SEPOLIA_RPC_URL"])
    account_addr = account_addr.strip() if account_addr else None
    if not account_addr:
        eprint("  Failed to read account address"); sys.exit(1)
    eprint(f"  Account: {account_addr}")

    eprint("  Funding account with 0.03 ETH...")
    cast_send(account_addr, "--value", "30000000000000000")

    state = {
        "account": account_addr,
        "spx_pk_seed": spx_pk_seed.hex(),
        "spx_pk_root": spx_pk_root.hex(),
        "slot_gen": 0,
        "sub_pk_seed": None,
        "sub_pk_root": None,
        "next_q": 1,
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    eprint(f"  State → {STATE_FILE}")
    print(f"JARDÍN SPX Account: {account_addr}")
    return state

def _nonce_of(account):
    env = load_env()
    raw = cast("call", ENTRYPOINT_V09, "getNonce(address,uint192)(uint256)",
               account, "0", "--rpc-url", env["SEPOLIA_RPC_URL"])
    if not raw: return 0
    raw = raw.strip()
    return int(raw, 0) if raw.startswith("0x") else int(raw)

def _build_type1_sig(account, nonce, spx_sk_seed, spx_sk_prf, spx_pk_seed, spx_pk_root,
                     sub_pk_seed_b16, sub_pk_root_b16, sig_counter):
    call_data = build_execute_calldata(account, 0)
    uop = build_user_op(account, nonce, "0x" + call_data.hex(), ver_gas=1_200_000)
    h = pack_user_op_hash(uop)
    env = load_env()
    ecdsa = Account.from_key(bytes.fromhex(env["PRIVATE_KEY"].replace("0x", "")))
    ecdsa_sig = ecdsa_sign(ecdsa, h)
    eprint(f"  Signing with SPX (sig_counter={sig_counter})...")
    # spx_sign takes `message: bytes` (32B). The verifier treats `message` as a bytes32.
    spx_sig_bytes = spx_sign(spx_pk_seed, spx_sk_seed, spx_sk_prf, spx_pk_root,
                              h, sig_counter)
    sig = bytes([0x01]) + ecdsa_sig + sub_pk_seed_b16 + sub_pk_root_b16 + spx_sig_bytes
    uop["signature"] = "0x" + sig.hex()
    return uop

def _build_type2_sig(account, nonce, sub_pk_seed, sub_sk_seed, sub_pk_root, levels, q):
    call_data = build_execute_calldata(account, 0)
    uop = build_user_op(account, nonce, "0x" + call_data.hex(), ver_gas=250_000)
    h = pack_user_op_hash(uop)
    env = load_env()
    ecdsa = Account.from_key(bytes.fromhex(env["PRIVATE_KEY"].replace("0x", "")))
    ecdsa_sig = ecdsa_sign(ecdsa, h)
    eprint(f"  Signing with FORS+C (q={q})...")
    forsc_sig, *_ = jardin_sign(sub_pk_seed, sub_sk_seed, sub_pk_root, levels,
                                 int.from_bytes(h, "big"), q)
    ss_b = int_to_b16_high(sub_pk_seed)
    sr_b = int_to_b16_high(sub_pk_root)
    sig = bytes([0x02]) + ecdsa_sig + ss_b + sr_b + forsc_sig
    uop["signature"] = "0x" + sig.hex()
    return uop

def cmd_cycle():
    eprint("=== JARDÍN SPX Cycle: 3× Type 1 + 3× Type 2 ===")
    if not os.path.exists(STATE_FILE):
        cmd_deploy()
        time.sleep(8)

    with open(STATE_FILE) as f:
        state = json.load(f)
    account = state["account"]

    spx_sk_seed, spx_sk_prf, spx_pk_seed, spx_pk_root = gen_spx_keys()
    assert spx_pk_root.hex() == state["spx_pk_root"], "SPX root mismatch vs state"

    results = []
    sub_pk_seed = sub_sk_seed = sub_pk_root = levels = None

    uop_nonce = _nonce_of(account)
    eprint(f"  Initial nonce: {uop_nonce}")

    for i in range(3):
        slot_gen = i + 1
        eprint(f"\n[Type 1 #{i+1}] Registering slot_gen={slot_gen}")
        sub_pk_seed, sub_sk_seed, sub_pk_root, levels = gen_sub_keys(slot_gen)
        sub_seed_b16 = int_to_b16_high(sub_pk_seed)
        sub_root_b16 = int_to_b16_high(sub_pk_root)
        uop = _build_type1_sig(account, uop_nonce,
                               spx_sk_seed, spx_sk_prf, spx_pk_seed, spx_pk_root,
                               sub_seed_b16, sub_root_b16, sig_counter=slot_gen)
        sig_bytes = len(bytes.fromhex(uop['signature'][2:]))
        eprint(f"  Submitting via Candide (sig bytes = {sig_bytes})")
        ok, cost, tx = submit_via_bundler(uop)
        results.append(("Type1", slot_gen, ok, cost, tx))
        tag = "OK" if ok else "FAIL"
        print(f"  Type1 slot_gen={slot_gen}  {tag}  cost={cost} wei  tx={tx}", flush=True)
        if ok:
            uop_nonce += 1
            state.update(slot_gen=slot_gen,
                         sub_pk_seed=hex(sub_pk_seed), sub_pk_root=hex(sub_pk_root),
                         next_q=1)
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        else:
            eprint("  Type 1 failed — abort.")
            return

    for q in range(1, 4):
        eprint(f"\n[Type 2 #{q}] Compact FORS+C on slot_gen={state['slot_gen']}, q={q}")
        uop = _build_type2_sig(account, uop_nonce,
                               sub_pk_seed, sub_sk_seed, sub_pk_root, levels, q)
        sig_bytes = len(bytes.fromhex(uop['signature'][2:]))
        eprint(f"  Submitting via Candide (sig bytes = {sig_bytes})")
        ok, cost, tx = submit_via_bundler(uop)
        results.append(("Type2", q, ok, cost, tx))
        tag = "OK" if ok else "FAIL"
        print(f"  Type2 q={q}  {tag}  cost={cost} wei  tx={tx}", flush=True)
        if ok:
            uop_nonce += 1
            state["next_q"] = q + 1
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)

    print("\n" + "=" * 60)
    t1 = [r for r in results if r[0] == "Type1"]
    t2 = [r for r in results if r[0] == "Type2"]
    t1_ok = [r[3] for r in t1 if r[2]]
    t2_ok = [r[3] for r in t2 if r[2]]
    print(f"Type 1: {sum(1 for r in t1 if r[2])}/{len(t1)} ok   "
          f"actualGasCost avg={sum(t1_ok)//len(t1_ok) if t1_ok else 0} wei")
    print(f"Type 2: {sum(1 for r in t2 if r[2])}/{len(t2)} ok   "
          f"actualGasCost avg={sum(t2_ok)//len(t2_ok) if t2_ok else 0} wei")
    for kind, key, ok, cost, tx in results:
        tag = "OK" if ok else "FAIL"
        print(f"  {kind} {key}  {tag}  tx={tx}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jardin_spx_userop.py [deploy|cycle|save-addresses <spx> <forsc> <factory>]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "save-addresses":
        if len(sys.argv) != 5:
            print("save-addresses <spxVerifier> <forscVerifier> <factory>")
            sys.exit(1)
        save_addresses(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "deploy":
        cmd_deploy()
    elif cmd == "cycle":
        cmd_cycle()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
