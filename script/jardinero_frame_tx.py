#!/usr/bin/env python3
"""
JARDINERO EIP-8141 Frame Transactions on ethrex (SPX variant).

Cycle: 3× Type 1 register → 3× Type 2 compact.

Usage: python3 script/jardinero_frame_tx.py [cycle|register [gen]|compact <q> [gen]]
"""

import sys, os, json, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jardin_spx_signer import (
    derive_spx_keys as spx_derive,
    build_pk_root as spx_build_root,
    spx_sign,
    keccak256 as _keccak_bytes,  # returns bytes
)
from jardin_signer import (
    build_balanced_tree, jardin_sign, Q_MAX,
)
from frame_tx import (
    build_frame_tx, compute_sig_hash, send_raw_tx,
    rpc_call, get_nonce, get_chain_id,
    MODE_VERIFY, MODE_SENDER, FRAME_TX_TYPE,
)

# ============================================================
#  Config
# ============================================================

ETHREX_RPC = "https://demo.eip-8141.ethrex.xyz/rpc"
DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

MAX_PRIORITY_FEE = 5_000_000_000
MAX_FEE          = 10_000_000_000

N_MASK_INT = (1 << 256) - (1 << 128)

def info_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardinero_ethrex.json")

def load_ethrex_info():
    with open(info_path()) as f:
        return json.load(f)

# ============================================================
#  Key derivation
# ============================================================

def keccak_int(data: bytes) -> int:
    return int.from_bytes(_keccak_bytes(data), "big")

def master_sk_bytes() -> bytes:
    return _keccak_bytes(bytes.fromhex(DEV_KEY) + b"jardinero_frame_spx_v1")

def make_spx_keys():
    master = master_sk_bytes()
    sk_seed, sk_prf, pk_seed = spx_derive(master)
    print("  Building SPX top-layer XMSS (16 WOTS+ keypairs)...", file=sys.stderr)
    pk_root = spx_build_root(pk_seed, sk_seed)
    return sk_seed, sk_prf, pk_seed, pk_root

def make_sub(gen=1):
    """Derive a FORS+C sub-key (ints with value in high 16B, matching jardin_signer)."""
    master = master_sk_bytes()
    sub_ent = _keccak_bytes(master + b"jardinero_device_spx_" + str(gen).encode())
    sub_pk_seed = keccak_int(b"jardinero_pk_seed" + sub_ent) & N_MASK_INT
    sub_sk_seed = keccak_int(b"jardinero_sk_seed" + sub_ent)
    print(f"  Building balanced FORS+C tree (gen={gen}, Q_MAX={Q_MAX})...", file=sys.stderr)
    t0 = time.time()
    levels, sub_pk_root = build_balanced_tree(sub_pk_seed, sub_sk_seed)
    print(f"  Keygen: {time.time()-t0:.1f}s", file=sys.stderr)
    return sub_pk_seed, sub_sk_seed, sub_pk_root, levels

# ============================================================
#  JARDINERO signature builders
# ============================================================

def spx_type1_register(sk_seed, sk_prf, pk_seed, pk_root,
                        sub_pk_int, sub_root_int, sig_hash_int, sig_counter):
    # spx_sign takes message as 32B bytes; sig_hash comes in as int from
    # frame_tx.compute_sig_hash. Pad/convert to bytes32.
    msg = sig_hash_int.to_bytes(32, "big")
    spx_sig = spx_sign(pk_seed, sk_seed, sk_prf, pk_root, msg, sig_counter)
    return (bytes([0x01]) +
            (sub_pk_int   >> 128).to_bytes(16, "big") +
            (sub_root_int >> 128).to_bytes(16, "big") + spx_sig)

def jardin_type2(sub_pk, sub_sk, sub_root, q, levels, sig_hash):
    forsc, *_ = jardin_sign(sub_pk, sub_sk, sub_root, levels, sig_hash, q)
    return (bytes([0x02]) +
            (sub_pk   >> 128).to_bytes(16, "big") +
            (sub_root >> 128).to_bytes(16, "big") + forsc)

# ============================================================
#  Frame data encoders
# ============================================================

def encode_register_slot(sub_pk, sub_root):
    sel = _keccak_bytes(b"registerSlot(bytes16,bytes16)")[:4]
    return (sel +
            (sub_pk   >> 128).to_bytes(16, "big").ljust(32, b"\x00") +
            (sub_root >> 128).to_bytes(16, "big").ljust(32, b"\x00"))

def encode_verify_data(sig_hash_int, sig_bytes):
    return sig_hash_int.to_bytes(32, "big") + sig_bytes

# ============================================================
#  Frame tx
# ============================================================

def send_frame_tx(rpc, chain_id, sender, nonce, jardin_sig, sig_hash_int, label,
                  sender_data=b"", verify_gas=2_000_000):
    verify_data = encode_verify_data(sig_hash_int, jardin_sig)
    frames_for_hash = [
        (MODE_VERIFY, sender, verify_gas, b""),
        (MODE_SENDER, sender, 100_000, b""),
    ]
    frames_final = [
        (MODE_VERIFY, sender, verify_gas, verify_data),
        (MODE_SENDER, sender, 100_000, sender_data),
    ]
    tx_for_hash = build_frame_tx(chain_id, nonce, sender, frames_for_hash,
                                  max_priority_fee=MAX_PRIORITY_FEE, max_fee=MAX_FEE)
    computed = compute_sig_hash(tx_for_hash)
    if computed != sig_hash_int:
        print(f"  WARN sig_hash mismatch: computed={hex(computed)[:18]} signed={hex(sig_hash_int)[:18]}",
              file=sys.stderr)

    final_payload = build_frame_tx(chain_id, nonce, sender, frames_final,
                                    max_priority_fee=MAX_PRIORITY_FEE, max_fee=MAX_FEE)
    raw_tx = bytes([FRAME_TX_TYPE]) + final_payload
    raw_hex = "0x" + raw_tx.hex()
    print(f"  raw tx size: {len(raw_tx)} bytes", file=sys.stderr)
    tx_hash = send_raw_tx(rpc, raw_hex)
    if not tx_hash:
        print(f"  {label}: SUBMIT FAILED")
        return None
    print(f"  {label}: submitted tx={tx_hash} — polling receipt...", flush=True)
    for _ in range(60):
        time.sleep(2)
        receipt = rpc_call(rpc, "eth_getTransactionReceipt", [tx_hash])
        if receipt:
            status = receipt.get("status", "?")
            gas = int(receipt.get("gasUsed", "0x0"), 16)
            frs = receipt.get("frameReceipts", [])
            fr_info = " ".join(f"F{i}={f.get('status','?')}" for i, f in enumerate(frs))
            ok = "success" if status == "0x1" else "failed"
            print(f"  {label}: gas={gas} {ok} {fr_info}", flush=True)
            return {"gas": gas, "status": ok, "tx": tx_hash, "frames": frs}
    print(f"  {label}: timed out waiting for receipt", flush=True)
    return {"gas": 0, "status": "submitted", "tx": tx_hash}

# ============================================================
#  Commands
# ============================================================

_local_nonce = [None]

def _nonce(rpc, sender):
    if _local_nonce[0] is None:
        _local_nonce[0] = get_nonce(rpc, sender)
    return _local_nonce[0]

def _advance_nonce():
    _local_nonce[0] += 1

def do_tx(rpc, chain_id, sender, label, sig_builder, sender_data=b"", verify_gas=2_000_000):
    nonce = _nonce(rpc, sender)
    frames_for_hash = [
        (MODE_VERIFY, sender, verify_gas, b""),
        (MODE_SENDER, sender, 100_000, b""),
    ]
    tx_for_hash = build_frame_tx(chain_id, nonce, sender, frames_for_hash,
                                   max_priority_fee=MAX_PRIORITY_FEE, max_fee=MAX_FEE)
    sig_hash = compute_sig_hash(tx_for_hash)
    jardin_sig = sig_builder(sig_hash)
    res = send_frame_tx(rpc, chain_id, sender, nonce, jardin_sig, sig_hash, label,
                        sender_data=sender_data, verify_gas=verify_gas)
    if res and res.get("status") == "success":
        _advance_nonce()
    return res

def cmd_cycle():
    info = load_ethrex_info()
    rpc = ETHREX_RPC
    chain_id = get_chain_id(rpc)
    sender = info["frame_proxy"]

    print(f"=== JARDINERO (SPX) Frame Cycle — 3× Type 1 + 3× Type 2 ===")
    print(f"Chain: {chain_id}  Sender: {sender}")
    sk_seed, sk_prf, pk_seed, pk_root = make_spx_keys()
    # Accept either "spx_pk_root" or (legacy) "t0_pk_root" in the info file so the
    # script keeps working across upgrades.
    deployed = info.get("spx_pk_root") or info.get("t0_pk_root")
    assert deployed is not None, "missing spx_pk_root/t0_pk_root in ethrex info"
    assert int(deployed, 16) == int.from_bytes(pk_root, "big") or \
           int(deployed, 16) == int.from_bytes(pk_root.ljust(32, b"\x00"), "big"), \
        f"pk_root mismatch: computed={pk_root.hex()} deployed={deployed}"

    results = []
    sub_pk = sub_sk = sub_root = levels = None

    for i in range(3):
        gen = i + 1
        print(f"\n[Type 1 #{gen}] Registering slot_gen={gen}")
        sub_pk, sub_sk, sub_root, levels = make_sub(gen)
        sender_data = encode_register_slot(sub_pk, sub_root)
        label = f"Type1 register (gen={gen})"
        res = do_tx(rpc, chain_id, sender, label,
                    lambda sh, _g=gen: spx_type1_register(
                        sk_seed, sk_prf, pk_seed, pk_root,
                        sub_pk, sub_root, sh, sig_counter=_g),
                    sender_data=sender_data)
        results.append({"kind": "Type1", "gen": gen, "res": res})
        if not res or res.get("status") != "success":
            print(f"  abort: {label} failed")
            return

    last_gen = max((r["gen"] for r in results if r["kind"] == "Type1"), default=None)
    for q in range(1, 4):
        print(f"\n[Type 2 #{q}] Compact FORS+C on gen={last_gen}, q={q}")
        label = f"Type2 q={q}"
        res = do_tx(rpc, chain_id, sender, label,
                    lambda sh, _q=q: jardin_type2(sub_pk, sub_sk, sub_root, _q, levels, sh))
        results.append({"kind": "Type2", "q": q, "res": res})

    print("\n" + "=" * 60)
    t1g = [r["res"]["gas"] for r in results if r["kind"] == "Type1" and r["res"] and r["res"]["gas"] > 0]
    t2g = [r["res"]["gas"] for r in results if r["kind"] == "Type2" and r["res"] and r["res"]["gas"] > 0]
    ok  = sum(1 for r in results if r["res"] and r["res"]["status"] == "success")
    print(f"Success: {ok}/{len(results)}")
    if t1g:
        print(f"Type 1 gas: min={min(t1g)} max={max(t1g)} avg={sum(t1g)//len(t1g)}")
    if t2g:
        print(f"Type 2 gas: min={min(t2g)} max={max(t2g)} avg={sum(t2g)//len(t2g)}")
    for r in results:
        res = r["res"]
        key = r.get("gen") or r.get("q")
        tx = res.get("tx") if res else None
        status = res.get("status") if res else "no-receipt"
        print(f"  {r['kind']} {key}  {status}  tx={tx}")

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    if cmd == "cycle":
        cmd_cycle()
    else:
        print(f"Usage: {sys.argv[0]} [cycle]")
        sys.exit(1)

if __name__ == "__main__":
    main()
