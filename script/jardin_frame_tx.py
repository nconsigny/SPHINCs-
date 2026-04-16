#!/usr/bin/env python3
"""
JARDÍN EIP-8141 Frame Transactions on ethrex.

Full cycle: Type 1 register → Type 1 emergency → 128×Type 2 → Type 1 register

Usage: python3 script/jardin_frame_tx.py [full|register|emergency|compact <q>]
"""

import sys, os, json, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import (sign_with_known_keys, derive_keys, keccak256, to_b32,
                    _build_hypertree_d2, VARIANTS, N_MASK)
from jardin_signer import (build_balanced_tree, jardin_sign,
                            N, K, A, Q_MAX, FORSC_BODY, FORSC_SIG_LEN, to_b4)
from frame_tx import (build_frame_tx, compute_sig_hash, send_raw_tx,
                       rpc_call, get_nonce, get_chain_id,
                       MODE_VERIFY, MODE_SENDER, FRAME_TX_TYPE)
import requests

# ============================================================
#  Config
# ============================================================

ETHREX_RPC = "https://demo.eip-8141.ethrex.xyz/rpc"
DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

def load_ethrex_info():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardin_ethrex.json")
    with open(p) as f:
        info = json.load(f)
    # Prefer frame_proxy (has APPROVE opcode) over bare Solidity contract
    if "frame_proxy" in info:
        info["frame"] = info["frame_proxy"]
    return info

# ============================================================
#  Keys (same as Sepolia frame account)
# ============================================================

def make_keys():
    entropy = keccak256(b"jardin_frame_v5_h7")
    seed, sk = derive_keys(entropy)
    cfg = VARIANTS["c11"]
    root = _build_hypertree_d2(seed, sk, cfg["subtree_h"], cfg)
    return seed, sk, root

def make_sub(sk, gen=1):
    sub_ent = keccak256(to_b32(sk) + b"jardin_device_" + str(gen).encode())
    sub_pk = keccak256(b"jardin_pk_seed" + to_b32(sub_ent)) & N_MASK
    sub_sk = keccak256(b"jardin_sk_seed" + to_b32(sub_ent))
    print(f"  Building balanced FORS+C tree (gen={gen}, Q_MAX={Q_MAX})...", file=sys.stderr)
    t0 = time.time()
    levels, sub_root = build_balanced_tree(sub_pk, sub_sk)
    print(f"  Keygen: {time.time()-t0:.1f}s", file=sys.stderr)
    return sub_pk, sub_sk, sub_root, levels

# ============================================================
#  JARDÍN signature builders
# ============================================================

def jardin_type1_register(seed, sk, root, sub_pk, sub_root, sig_hash):
    c11 = sign_with_known_keys("c11", sig_hash, seed, sk, root)
    return (bytes([0x01]) +
            (sub_pk >> 128).to_bytes(16, "big") +
            (sub_root >> 128).to_bytes(16, "big") + c11)

def jardin_type1_emergency(seed, sk, root, sig_hash):
    c11 = sign_with_known_keys("c11", sig_hash, seed, sk, root)
    # subSeed=0, subRoot=0 ⇒ stateless fallback (no registration)
    return bytes([0x01]) + bytes(16) + bytes(16) + c11

def jardin_type2(sub_pk, sub_sk, sub_root, q, levels, sig_hash):
    forsc, _, _, _ = jardin_sign(sub_pk, sub_sk, sub_root, levels, sig_hash, q)
    return (bytes([0x02]) +
            (sub_pk >> 128).to_bytes(16, "big") +
            (sub_root >> 128).to_bytes(16, "big") + forsc)

# ============================================================
#  ABI encode verifyAndApprove call
# ============================================================

def encode_register_slot(sub_pk, sub_root):
    """ABI-encode registerSlot(bytes16 subSeed, bytes16 subRoot)."""
    from Crypto.Hash import keccak as _k
    h = _k.new(digest_bits=256)
    h.update(b"registerSlot(bytes16,bytes16)")
    sel = h.digest()[:4]
    return (sel +
            (sub_pk >> 128).to_bytes(16, "big").ljust(32, b'\x00') +
            (sub_root >> 128).to_bytes(16, "big").ljust(32, b'\x00'))


def encode_verify_data(sig_hash_int, jardin_sig):
    """Encode VERIFY frame data: sigHash(32) || raw_sig(N).
    Raw concatenation — no ABI wrapping. This is the only format ethrex mines."""
    return sig_hash_int.to_bytes(32, "big") + jardin_sig

# ============================================================
#  Send frame tx
# ============================================================

def send_frame_tx(rpc, chain_id, sender, nonce, jardin_sig, sig_hash_int, label,
                   sender_data=b''):
    """Build and send a type-6 frame transaction.
    VERIFY frame: sigHash || jardin_sig (read-only verification + APPROVE)
    SENDER frame: sender_data (state changes — slot registration, execute, etc.)
    """
    verify_data = encode_verify_data(sig_hash_int, jardin_sig)

    # Frames for sig_hash (VERIFY data elided per EIP-8141)
    frames_for_hash = [
        (MODE_VERIFY, sender, 500_000, b''),
        (MODE_SENDER, sender, 100_000, b''),
    ]
    frames_final = [
        (MODE_VERIFY, sender, 500_000, verify_data),
        (MODE_SENDER, sender, 100_000, sender_data),
    ]

    # Compute sig_hash (with VERIFY data elided per EIP-8141)
    tx_for_hash = build_frame_tx(chain_id, nonce, sender, frames_for_hash)
    computed_hash = compute_sig_hash(tx_for_hash)

    # Sanity: the sig_hash we signed must match
    if computed_hash != sig_hash_int:
        print(f"  WARNING: sig_hash mismatch! computed={hex(computed_hash)[:18]} signed={hex(sig_hash_int)[:18]}", file=sys.stderr)

    # Build final tx
    final_payload = build_frame_tx(chain_id, nonce, sender, frames_final)
    raw_tx = bytes([FRAME_TX_TYPE]) + final_payload
    raw_hex = "0x" + raw_tx.hex()

    # Submit
    tx_hash = send_raw_tx(rpc, raw_hex)
    if not tx_hash:
        print(f"  {label}: SUBMIT FAILED")
        return None

    # Quick poll (3 attempts × 2s) — don't block for slow chains
    for _ in range(3):
        time.sleep(2)
        receipt = rpc_call(rpc, "eth_getTransactionReceipt", [tx_hash])
        if receipt:
            status = receipt.get("status", "?")
            gas = int(receipt.get("gasUsed", "0x0"), 16)
            frame_receipts = receipt.get("frameReceipts", [])
            fr_info = ""
            for i, fr in enumerate(frame_receipts):
                fr_info += f" F{i}={fr.get('status','?')}"
            ok = "success" if status == "0x1" else "failed"
            print(f"  {label}: gas={gas} {ok}{fr_info} tx={tx_hash[:18]}...", flush=True)
            return {"gas": gas, "status": ok, "tx": tx_hash}
    # Not confirmed yet — return hash for batch collection
    print(f"  {label}: submitted tx={tx_hash[:18]}...", flush=True)
    return {"gas": 0, "status": "submitted", "tx": tx_hash}

# ============================================================
#  Full cycle
# ============================================================

_local_nonce = [None]

def do_tx(rpc, chain_id, sender, label, sig_builder, sender_data=b''):
    if _local_nonce[0] is None:
        _local_nonce[0] = get_nonce(rpc, sender)
    nonce = _local_nonce[0]
    _local_nonce[0] += 1
    frames_for_hash = [
        (MODE_VERIFY, sender, 500_000, b''),
        (MODE_SENDER, sender, 100_000, b''),
    ]
    tx_for_hash = build_frame_tx(chain_id, nonce, sender, frames_for_hash)
    sig_hash = compute_sig_hash(tx_for_hash)
    jardin_sig = sig_builder(sig_hash)
    return send_frame_tx(rpc, chain_id, sender, nonce, jardin_sig, sig_hash, label,
                         sender_data=sender_data)


def cmd_register(rpc, chain_id, sender, seed, sk, root, gen):
    print(f"========== REGISTER (gen={gen}) ==========")
    sub_pk, sub_sk, sub_root, levels = make_sub(sk, gen)
    res = do_tx(rpc, chain_id, sender, f"Type1 register (gen={gen})",
                lambda sh: jardin_type1_register(seed, sk, root, sub_pk, sub_root, sh))
    return sub_pk, sub_sk, sub_root, levels, res


def cmd_compact(rpc, chain_id, sender, sk, gen, q):
    print(f"========== COMPACT q={q} (gen={gen}) ==========")
    sub_pk, sub_sk, sub_root, levels = make_sub(sk, gen)
    return do_tx(rpc, chain_id, sender, f"Type2 q={q} (gen={gen})",
                 lambda sh: jardin_type2(sub_pk, sub_sk, sub_root, q, levels, sh))


def cmd_full(rpc, chain_id, sender, seed, sk, root):
    results = []
    tx_num = [0]

    def _do(label, sig_builder, sender_data=b''):
        tx_num[0] += 1
        full_label = f"#{tx_num[0]:2d} {label}"
        res = do_tx(rpc, chain_id, sender, full_label, sig_builder, sender_data=sender_data)
        if res:
            results.append({"n": tx_num[0], "label": label, "gas": res["gas"], "ok": res["status"]})
        else:
            results.append({"n": tx_num[0], "label": label, "ok": "failed"})

    # ── SLOT 1: Register (VERIFY verifies C11, SENDER writes slot) ──
    print("========== SLOT 1: REGISTER ==========")
    sub_pk, sub_sk, sub_root, levels = make_sub(sk, 1)
    reg1_data = encode_register_slot(sub_pk, sub_root)
    _do("Type1 register (slot 1)",
        lambda sh: jardin_type1_register(seed, sk, root, sub_pk, sub_root, sh),
        sender_data=reg1_data)

    # ── Stateless fallback (no registration — SENDER frame is noop) ──
    print("\n========== STATELESS FALLBACK ==========")
    _do("Type1 stateless (sub=0)",
        lambda sh: jardin_type1_emergency(seed, sk, root, sh))

    # ── Q_MAX compact sigs (VERIFY verifies FORS+C, SENDER is noop) ──
    print(f"\n========== SLOT 1: TYPE 2 q=1..{Q_MAX} ==========")
    for q in range(1, Q_MAX + 1):
        _do(f"Type2 q={q}",
            lambda sh, _q=q: jardin_type2(sub_pk, sub_sk, sub_root, _q, levels, sh))

    # ── SLOT 2: Register ──
    print("\n========== SLOT 2: REGISTER ==========")
    sub_pk2, sub_sk2, sub_root2, levels2 = make_sub(sk, 2)
    reg2_data = encode_register_slot(sub_pk2, sub_root2)
    _do("Type1 register (slot 2)",
        lambda sh: jardin_type1_register(seed, sk, root, sub_pk2, sub_root2, sh),
        sender_data=reg2_data)

    # ── SLOT 2: one compact tx in the fresh slot ──
    print("\n========== SLOT 2: TYPE 2 q=1 ==========")
    _do("Type2 q=1 (slot 2)",
        lambda sh: jardin_type2(sub_pk2, sub_sk2, sub_root2, 1, levels2, sh))

    # Collect receipts for any unconfirmed txs
    pending = [r for r in results if r.get("ok") == "submitted" and r.get("tx")]
    if pending:
        print(f"\n========== COLLECTING {len(pending)} RECEIPTS ==========", flush=True)
        for attempt in range(30):
            time.sleep(3)
            still_pending = []
            for r in pending:
                receipt = rpc_call(rpc, "eth_getTransactionReceipt", [r["tx"]])
                if receipt:
                    gas = int(receipt.get("gasUsed", "0x0"), 16)
                    ok = "success" if receipt.get("status") == "0x1" else "failed"
                    r["gas"] = gas
                    r["ok"] = ok
                    frs = receipt.get("frameReceipts", [])
                    fr_info = " ".join(f"F{i}={f.get('status','?')}" for i,f in enumerate(frs))
                    print(f"  #{r['n']:2d} {r['label']:35s} gas={gas} {ok} {fr_info}", flush=True)
                else:
                    still_pending.append(r)
            pending = still_pending
            if not pending:
                break
        if pending:
            print(f"  {len(pending)} txs still pending after timeout")

    print("\n========== SUMMARY ==========", flush=True)
    ok = sum(1 for r in results if r.get("ok") == "success")
    fail = sum(1 for r in results if r.get("ok") == "failed")
    pend = sum(1 for r in results if r.get("ok") in ("submitted", "pending"))
    print(f"Total: {len(results)}  Success: {ok}  Failed: {fail}  Pending: {pend}")
    t1g = [r["gas"] for r in results if "Type1" in r["label"] and r.get("gas", 0) > 0]
    t2g = [r["gas"] for r in results if "Type2" in r["label"] and r.get("gas", 0) > 0]
    if t1g:
        print(f"Type 1: min={min(t1g)} max={max(t1g)} avg={sum(t1g)//len(t1g)}")
    if t2g:
        print(f"Type 2: min={min(t2g)} max={max(t2g)} avg={sum(t2g)//len(t2g)}")
        print(f"  q=1:   {t2g[0]}")
        if len(t2g) > 63: print(f"  q=64:  {t2g[63]}")
        print(f"  q={Q_MAX}: {t2g[-1]}")


def main():
    info = load_ethrex_info()
    rpc = ETHREX_RPC
    chain_id = get_chain_id(rpc)
    sender = info["frame"]
    seed, sk, root = make_keys()

    cmd = sys.argv[1] if len(sys.argv) > 1 else "full"

    if cmd == "register":
        gen = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        cmd_register(rpc, chain_id, sender, seed, sk, root, gen)

    elif cmd == "emergency":
        do_tx(rpc, chain_id, sender, "Type1 emergency (r=0)",
              lambda sh: jardin_type1_emergency(seed, sk, root, sh))

    elif cmd == "compact":
        q = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        gen = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        cmd_compact(rpc, chain_id, sender, sk, gen, q)

    elif cmd == "full":
        cmd_full(rpc, chain_id, sender, seed, sk, root)

    else:
        print(f"Usage: {sys.argv[0]} [full|register [gen]|emergency|compact <q> [gen]]")
        sys.exit(1)


if __name__ == "__main__":
    main()
