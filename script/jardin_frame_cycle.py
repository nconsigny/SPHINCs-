#!/usr/bin/env python3
"""
JARDÍN Frame Account — full lifecycle on Sepolia.
Type 1 register → Type 1 emergency → Q_MAX×Type 2 → Type 1 register (new slot)

Balanced h=7 tree: Q_MAX=128 compact sigs per slot.
"""

import sys, os, time, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer import (sign_with_known_keys, derive_keys, keccak256, to_b32,
                    _build_hypertree_d2, VARIANTS, N_MASK)
from jardin_signer import (build_balanced_tree, jardin_sign,
                            N, K, A, Q_MAX, FORSC_BODY, FORSC_SIG_LEN, to_b4)

FRAME_ACCOUNT = "0xbb7b6e20ea0dc7888e69a4eee27a9ec94ef5400f"

def load_env():
    env = {}
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    with open(p) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

def cast_send(to, sig_str, args, env):
    cmd = [os.path.expanduser("~/.foundry/bin/cast"), "send", to, sig_str] + args + [
        "--rpc-url", env["SEPOLIA_RPC_URL"], "--private-key", env["PRIVATE_KEY"]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          env={**os.environ, **env})
    if proc.returncode != 0:
        return None, proc.stderr.strip()[:120]
    gas = status = tx = ""
    for line in proc.stdout.split("\n"):
        if "gasUsed" in line: gas = line.split()[-1]
        if "status" in line and "(" in line: status = line.split()[-1].strip("()")
        if "transactionHash" in line: tx = line.split()[-1]
    return {"gas": gas, "status": status, "tx": tx}, None

def make_keys():
    entropy = keccak256(b"jardin_frame_test_v1")
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
    print(f"  Keygen done: {time.time()-t0:.1f}s", file=sys.stderr)
    return sub_pk, sub_sk, sub_root, levels

def msg(i):
    return keccak256(b"jardin_frame_msg" + i.to_bytes(4, "big"))

def sig_type1_register(seed, sk, root, sub_pk, sub_root, m):
    c11 = sign_with_known_keys("c11", m, seed, sk, root)
    return (bytes([0x01]) +
            (sub_pk >> 128).to_bytes(16, "big") +
            (sub_root >> 128).to_bytes(16, "big") + c11)

def sig_type1_emergency(seed, sk, root, m):
    c11 = sign_with_known_keys("c11", m, seed, sk, root)
    return bytes([0x01]) + bytes(16) + bytes(16) + c11

def sig_type2(sub_pk, sub_sk, sub_root, q, levels, m):
    forsc, _, _, _ = jardin_sign(sub_pk, sub_sk, sub_root, levels, m, q)
    return (bytes([0x02]) +
            (sub_pk >> 128).to_bytes(16, "big") +
            (sub_root >> 128).to_bytes(16, "big") + forsc)

def main():
    env = load_env()
    seed, sk, root = make_keys()
    results = []
    tx_num = 0

    def send(label, m, sig_bytes):
        nonlocal tx_num
        tx_num += 1
        res, err = cast_send(FRAME_ACCOUNT,
                             "verifyAndApprove(bytes32,bytes,uint256)",
                             [f"0x{m:064x}", "0x" + sig_bytes.hex(), "1"], env)
        if res:
            results.append({"n": tx_num, "label": label, "sig": len(sig_bytes),
                            "gas": res["gas"], "ok": res["status"]})
            print(f"#{tx_num:2d} {label:35s} sig={len(sig_bytes):5d}B gas={res['gas']:>7s} {res['status']}")
        else:
            results.append({"n": tx_num, "label": label, "ok": "FAIL"})
            print(f"#{tx_num:2d} {label:35s} FAILED: {err}")
        time.sleep(4)

    # ── SLOT 1: Register ──
    print("========== SLOT 1: REGISTER ==========")
    sub_pk, sub_sk, sub_root, levels = make_sub(sk, 1)
    send("Type1 register (slot 1)", msg(1), sig_type1_register(seed, sk, root, sub_pk, sub_root, msg(1)))

    # ── Stateless fallback ──
    print("\n========== STATELESS FALLBACK ==========")
    send("Type1 stateless (sub=0)", msg(2), sig_type1_emergency(seed, sk, root, msg(2)))

    # ── Q_MAX compact sigs ──
    print(f"\n========== SLOT 1: TYPE 2 q=1..{Q_MAX} ==========")
    for q in range(1, Q_MAX + 1):
        send(f"Type2 q={q}", msg(100 + q), sig_type2(sub_pk, sub_sk, sub_root, q, levels, msg(100 + q)))

    # ── SLOT 2: Register (final) ──
    print("\n========== SLOT 2: REGISTER ==========")
    sub_pk2, _sub_sk2, sub_root2, _levels2 = make_sub(sk, 2)
    send("Type1 register (slot 2)", msg(200), sig_type1_register(seed, sk, root, sub_pk2, sub_root2, msg(200)))

    # ── Summary ──
    print("\n========== SUMMARY ==========")
    ok = sum(1 for r in results if r.get("ok") == "success")
    fail = len(results) - ok
    print(f"Total: {len(results)}  Success: {ok}  Failed: {fail}")

    t1g = [int(r["gas"]) for r in results if "Type1" in r["label"] and r.get("gas")]
    t2g = [int(r["gas"]) for r in results if "Type2" in r["label"] and r.get("gas")]
    if t1g:
        print(f"Type 1: min={min(t1g)} max={max(t1g)} avg={sum(t1g)//len(t1g)}")
    if t2g:
        print(f"Type 2: min={min(t2g)} max={max(t2g)} avg={sum(t2g)//len(t2g)}")
        print(f"  q=1:   {t2g[0]} gas")
        print(f"  q=64:  {t2g[63] if len(t2g)>63 else 'N/A'} gas")
        print(f"  q={Q_MAX}: {t2g[-1]} gas")

if __name__ == "__main__":
    main()
