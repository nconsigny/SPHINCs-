#!/usr/bin/env python3
"""
Constrained SPHINCS parameter sweep around Fluhrer-Dang style forgery objective,
with family modes for FORS+C and PORS+FP.

Default constraints match the current discussion:
- q = 2^20 signatures
- keygen <= 120s on both SE profiles (70 MHz, 48 MHz)
- signer workload cap (default: Blockstream-aligned full signer hash-call budget,
  calibrated to current C2 baseline)
- security >= 120 bits

Security model (Fluhrer-Dang style expectation over instance reuse):
Pr[forge] <= sum_r Bin(q, 2^-h; r) * (1 - (1 - p_hit)^r)^k

where p_hit is per-signature probability that one target secret element is
revealed within a reused instance:
- FORS+C: p_hit = 2^-a
- PORS+FP: p_hit = k / 2^tree_height (tree padded to power of two)
"""

from __future__ import annotations

import argparse
import bisect
import math
import random
from dataclasses import dataclass


# Signature/layout constants for this repo's EVM implementation.
N = 16
W = 16
LEN1 = 32  # ceil((8*N)/log2(W)) for N=16, W=16
TARGET_SUM = 240  # WOTS+C fixed digit sum in this repository

# Hardware timing assumptions from user notes.
KECCAK_TIME_70MHZ_S = 186e-6
KECCAK_TIME_48MHZ_S = 271e-6

# Gas model constants (calibrated against local AsmBenchmark/E2E measurements).
# asm_gas_est ~= ASM_MODEL_INTERCEPT + ASM_MODEL_PER_OP * verify_ops_metric(...)
ASM_MODEL_INTERCEPT = 36117.58115183245
ASM_MODEL_PER_OP = 194.2041884816754

# PORS+FP verify-op proxy term:
# pors_core ~= 2*mMax + k + 5*tree_height + 27
PORS_CORE_TREE_H_WEIGHT = 5
PORS_CORE_CONST = 27

# Calldata model (same assumptions as test/AsmBenchmark.t.sol).
TX_BASE_GAS = 21_000
CALLDATA_NZ_RATIO_NUM = 97
CALLDATA_NZ_RATIO_DEN = 100
CALLDATA_OVERHEAD_NZ_BYTES = 100
CALLDATA_STD_NZ_GAS = 16
CALLDATA_STD_Z_GAS = 4
CALLDATA_FLOOR_NZ_GAS = 60
CALLDATA_FLOOR_Z_GAS = 15

# Current C2 baseline (h=18,d=2,k=13,a=13) for signer-cap calibration.
BASELINE_C2_H = 18
BASELINE_C2_D = 2
BASELINE_C2_K = 13
BASELINE_C2_A = 13

# Legacy cap mode: only FORS leaf-count proxy.
DEFAULT_SIGNER_CAP_K2A = BASELINE_C2_K * (1 << BASELINE_C2_A)

# Blockstream-aligned mode: full signer hash-call budget (FORS+C + hypertree sign path).
# Computed from signer_work_fors_c_calls(BASELINE_C2_*): 854,495 calls.
DEFAULT_SIGNER_CAP_BLOCKSTREAM = 854_495


@dataclass
class OctopusStats:
    k: int
    tree_height: int
    samples: int
    quantile: float
    observed_max: int
    quantile_mmax: int
    quantile_accept_prob: float
    mean_nodes: float


@dataclass
class Candidate:
    family: str
    h: int
    d: int
    k: int
    a: int
    q: int
    tree_height: int
    m_max: int | None
    m_accept_prob: float | None
    m_expected_trials: float | None
    p_hit: float
    sec_bits: float
    forge_prob: float
    lambda_reuse: float
    signer_work: int
    sig_size: int
    keygen_keccak_calls: int
    keygen_70_s: float
    keygen_48_s: float


@dataclass
class SecurityBudget:
    q_target: int
    lambda_reuse: float


def ceil_log2(x: int) -> int:
    if x <= 1:
        return 0
    return (x - 1).bit_length()


def pors_tree_height(k: int, a: int) -> int:
    t = k * (1 << a)
    return ceil_log2(t)


def sig_size_full_fors(h: int, d: int, k: int, a: int) -> int:
    """R + k secrets + k auth paths + d hypertree layers."""
    subtree_h = h // d
    layer_size = LEN1 * N + 4 + subtree_h * N
    return N + k * N + k * a * N + d * layer_size


def sig_size_fors_c(h: int, d: int, k: int, a: int) -> int:
    """R + k secrets + (k-1) auth paths + d hypertree layers."""
    subtree_h = h // d
    layer_size = LEN1 * N + 4 + subtree_h * N
    return N + k * N + (k - 1) * a * N + d * layer_size


def sig_size_pors_fp(h: int, d: int, k: int, m_max: int) -> int:
    """R + k PORS secrets + m_max octopus auth nodes + d hypertree layers."""
    subtree_h = h // d
    layer_size = LEN1 * N + 4 + subtree_h * N
    return N + k * N + m_max * N + d * layer_size


def keygen_keccak_calls(h: int, d: int, w: int = W, len1: int = LEN1) -> int:
    """
    Approximate keygen cost for top-subtree root build in this codebase.
    calls ~= leaves * (len1 * w + 1) + (leaves - 1)
    """
    subtree_h = h // d
    leaves = 1 << subtree_h
    per_leaf = len1 * w + 1
    return leaves * per_leaf + (leaves - 1)


def signer_work_fors_c_calls(
    h: int,
    d: int,
    k: int,
    a: int,
    w: int = W,
    len1: int = LEN1,
    target_sum: int = TARGET_SUM,
) -> int:
    """
    Approximate signer work as hash/compression calls for W+C + FORS+C.

    Components (no subtree caching):
    1) FORS+C signing:
       - k full FORS tree builds
       - forced-zero R grind (expected 2^a digest hashes)
       - FORS root compression
       Approx formula from script/signer.py path:
         (3k + 1)*2^a + 1
    2) Hypertree signing:
       - d full subtree builds (one per layer)
       - WOTS chain progression for sigma (TARGET_SUM calls/layer)
    """
    subtree_h = h // d
    leaves_subtree = 1 << subtree_h
    leaves_fors = 1 << a

    per_subtree = leaves_subtree * (len1 * w + 1) + (leaves_subtree - 1)
    hypertree_sign = d * per_subtree + d * target_sum

    fors_c_sign = (3 * k + 1) * leaves_fors + 1

    return hypertree_sign + fors_c_sign


def signer_work_pors_fp_calls(
    h: int,
    d: int,
    k: int,
    tree_height: int,
    m_accept_prob: float,
    w: int = W,
    len1: int = LEN1,
    target_sum: int = TARGET_SUM,
) -> tuple[int, float]:
    """
    Approximate signer work as hash/compression calls for W+C + PORS+FP.

    Components (no subtree caching):
    1) PORS+FP signing:
       - Build one PORS tree of size T=2^tree_height:
         * leaf hashing: (T-k)*1 + k*2 = T + k (dummy leaves vs selected secret+th)
         * internal parent hashes: T-1
         * packed secret list materialization: +k
       - R grind for octopus-cap acceptance:
         expected trials = 1 / m_accept_prob
         per trial hash calls ~= 1 (H_msg) + ext_calls_for_index_extraction
    2) Hypertree signing:
       - d full subtree builds (one per layer)
       - WOTS chain progression for sigma (TARGET_SUM calls/layer)

    Returns:
      (signer_work_calls, expected_trials)
    """
    subtree_h = h // d
    leaves_subtree = 1 << subtree_h
    t_leaves = 1 << tree_height

    per_subtree = leaves_subtree * (len1 * w + 1) + (leaves_subtree - 1)
    hypertree_sign = d * per_subtree + d * target_sum

    pors_tree_build = (t_leaves + k) + (t_leaves - 1) + k

    chunk = max(1, 256 // tree_height)
    ext_calls_per_trial = max(1, math.ceil(k / chunk))
    trial_cost = 1 + ext_calls_per_trial
    expected_trials = 1.0 / max(m_accept_prob, 1e-12)
    r_grind_calls = int(math.ceil(expected_trials * trial_cost))

    return hypertree_sign + pors_tree_build + r_grind_calls, expected_trials


def verify_ops_metric(
    family: str,
    h: int,
    d: int,
    k: int,
    a: int,
    tree_height: int,
    m_max: int | None,
) -> int:
    """
    Coarse verify-operation proxy calibrated to this repo's asm verifier gas.

    FORS+C core: (k-1)*(a+1) + 3
    PORS+FP core: 2*mMax + k + 5*tree_height + 27
    Both add hypertree/WOTS term: d*(242 + subtree_h), subtree_h=h/d.
    """
    subtree_h = h // d
    hypertree_term = d * (242 + subtree_h)

    if family == "fors_c":
        core = (k - 1) * (a + 1) + 3
    else:
        m = 0 if m_max is None else m_max
        core = 2 * m + k + PORS_CORE_TREE_H_WEIGHT * tree_height + PORS_CORE_CONST

    return core + hypertree_term


def estimate_asm_verify_gas(
    family: str,
    h: int,
    d: int,
    k: int,
    a: int,
    tree_height: int,
    m_max: int | None,
) -> int:
    ops = verify_ops_metric(
        family=family,
        h=h,
        d=d,
        k=k,
        a=a,
        tree_height=tree_height,
        m_max=m_max,
    )
    g = ASM_MODEL_INTERCEPT + ASM_MODEL_PER_OP * ops
    return max(0, int(round(g)))


def estimate_total_tx_gas(sig_size: int, asm_verify_gas: int) -> tuple[int, bool]:
    """
    Estimate total tx gas for a verify call under EIP-7623 floor mechanics.
    Returns (tx_gas, floor_dominated).
    """
    nz = (sig_size * CALLDATA_NZ_RATIO_NUM) // CALLDATA_NZ_RATIO_DEN + CALLDATA_OVERHEAD_NZ_BYTES
    z = sig_size - (sig_size * CALLDATA_NZ_RATIO_NUM) // CALLDATA_NZ_RATIO_DEN

    std_cd = nz * CALLDATA_STD_NZ_GAS + z * CALLDATA_STD_Z_GAS
    floor_cd = nz * CALLDATA_FLOOR_NZ_GAS + z * CALLDATA_FLOOR_Z_GAS

    tx_std_path = TX_BASE_GAS + std_cd + asm_verify_gas
    tx_floor_path = TX_BASE_GAS + floor_cd
    floor_dom = tx_floor_path >= tx_std_path
    return max(tx_std_path, tx_floor_path), floor_dom


def octopus_auth_nodes_count(sorted_indices: list[int], tree_height: int) -> int:
    """Count Octopus auth nodes for sorted unique indices."""
    current = list(sorted_indices)
    count = 0
    for _ in range(tree_height):
        nxt: list[int] = []
        j = 0
        while j < len(current):
            idx = current[j]
            sibling = idx ^ 1
            if j + 1 < len(current) and current[j + 1] == sibling:
                nxt.append(idx >> 1)
                j += 2
            else:
                count += 1
                nxt.append(idx >> 1)
                j += 1
        current = nxt
    return count


def sample_octopus_stats(
    k: int,
    tree_height: int,
    samples: int,
    quantile: float,
    seed: int,
) -> OctopusStats:
    """Monte Carlo model for Octopus auth-node count distribution."""
    rng = random.Random(seed + 1315423911 * k + 2654435761 * tree_height)
    t_leaves = 1 << tree_height

    counts: list[int] = []
    for _ in range(samples):
        idx = sorted(rng.sample(range(t_leaves), k))
        counts.append(octopus_auth_nodes_count(idx, tree_height))

    counts.sort()
    n = len(counts)

    q_idx = min(n - 1, max(0, int(math.ceil(quantile * n) - 1)))
    q_mmax = counts[q_idx]
    q_accept = bisect.bisect_right(counts, q_mmax) / n

    return OctopusStats(
        k=k,
        tree_height=tree_height,
        samples=samples,
        quantile=quantile,
        observed_max=counts[-1],
        quantile_mmax=q_mmax,
        quantile_accept_prob=q_accept,
        mean_nodes=sum(counts) / n,
    )


def fluhrer_dang_forge_prob(q: int, h: int, k: int, p_hit: float, eps_tail: float = 1e-16) -> float:
    """
    Compute:
      sum_r Bin(q, 2^-h; r) * (1 - (1 - p_hit)^r)^k
    using stable binomial recurrence and tail truncation.
    """
    p = 2.0 ** (-h)
    if p_hit <= 0.0:
        return 0.0
    if p_hit >= 1.0:
        return 1.0

    prob_r = (1.0 - p) ** q
    cdf = prob_r
    forge = 0.0

    r = 0
    log_one_minus_p_hit = math.log1p(-p_hit)
    while r < q:
        r_next = r + 1
        ratio = ((q - r) / r_next) * (p / (1.0 - p))
        prob_r *= ratio
        r = r_next
        cdf += prob_r

        if prob_r == 0.0 or prob_r < 1e-300:
            break

        one_minus_pow = -math.expm1(r * log_one_minus_p_hit)
        term = one_minus_pow ** k
        forge += prob_r * term

        if 1.0 - cdf <= eps_tail:
            break

    if forge < 0.0:
        forge = 0.0
    return forge


def security_bits_from_prob(prob: float) -> float:
    if prob <= 0.0:
        return float("inf")
    return -math.log2(prob)


def _fmt_int_with_commas(x: int) -> str:
    return f"{x:,}"


def _fmt_lambda(x: float) -> str:
    if x >= 1e6 or (x > 0.0 and x < 1e-3):
        return f"{x:.2e}"
    return f"{x:.3f}"


def _find_q_for_security_target(
    h: int,
    k: int,
    p_hit: float,
    target_bits: float,
    q_start: int,
    q_max: int,
) -> SecurityBudget:
    """
    Find max q where sec_bits(q) >= target_bits using exponential bracketing
    then integer binary search.
    """
    q_start = max(1, q_start)
    q_max = max(q_start, q_max)

    cache: dict[int, float] = {}

    def sec_at(q: int) -> float:
        if q not in cache:
            cache[q] = security_bits_from_prob(fluhrer_dang_forge_prob(q, h, k, p_hit))
        return cache[q]

    low = 0
    high = q_start

    if sec_at(high) >= target_bits:
        low = high
        while high < q_max and sec_at(high) >= target_bits:
            low = high
            high = min(q_max, high * 2)
            if high == low:
                break
        if sec_at(high) >= target_bits:
            q_target = high
            return SecurityBudget(q_target=q_target, lambda_reuse=q_target / (2.0 ** h))
    else:
        while high > 1 and sec_at(high) < target_bits:
            high = max(1, high // 2)
        if sec_at(high) < target_bits:
            return SecurityBudget(q_target=0, lambda_reuse=0.0)
        low = 0

    while low + 1 < high:
        mid = (low + high) // 2
        if sec_at(mid) >= target_bits:
            low = mid
        else:
            high = mid

    q_target = low
    return SecurityBudget(q_target=q_target, lambda_reuse=q_target / (2.0 ** h))


def selected_families(args: argparse.Namespace) -> list[str]:
    if args.family == "all":
        return ["fors_c", "pors_fp"]
    return [args.family]


def signer_work_metric(
    args: argparse.Namespace,
    family: str,
    h: int,
    k: int,
    a: int,
    tree_height: int,
    m_accept_prob: float | None,
) -> tuple[int, float | None]:
    if args.signer_cap_mode == "k2a":
        return k * (1 << a), None

    if family == "fors_c":
        return signer_work_fors_c_calls(h=h, d=args.d, k=k, a=a), None

    assert m_accept_prob is not None
    calls, expected_trials = signer_work_pors_fp_calls(
        h=h,
        d=args.d,
        k=k,
        tree_height=tree_height,
        m_accept_prob=m_accept_prob,
    )
    return calls, expected_trials


def sweep(args: argparse.Namespace) -> list[Candidate]:
    out: list[Candidate] = []
    octopus_cache: dict[tuple[int, int], OctopusStats] = {}

    for h in range(args.h_min, args.h_max + 1):
        if h % args.d != 0:
            continue

        calls = keygen_keccak_calls(h, args.d)
        keygen_70 = calls * KECCAK_TIME_70MHZ_S
        keygen_48 = calls * KECCAK_TIME_48MHZ_S
        if keygen_70 > args.keygen_max_s or keygen_48 > args.keygen_max_s:
            continue

        lam = args.q / (2.0 ** h)

        for k in range(args.k_min, args.k_max + 1):
            for a in range(args.a_min, args.a_max + 1):
                for family in selected_families(args):
                    tree_h = a
                    m_max: int | None = None
                    m_accept_prob: float | None = None

                    if family == "fors_c":
                        p_hit = 2.0 ** (-a)
                        sig_size = sig_size_fors_c(h, args.d, k, a)
                    else:
                        tree_h = pors_tree_height(k, a)
                        cache_key = (k, tree_h)
                        if cache_key not in octopus_cache:
                            octopus_cache[cache_key] = sample_octopus_stats(
                                k=k,
                                tree_height=tree_h,
                                samples=args.pors_samples,
                                quantile=args.pors_quantile,
                                seed=args.pors_seed,
                            )
                        stats = octopus_cache[cache_key]

                        if args.pors_mmax_policy == "max":
                            m_max = stats.observed_max
                            m_accept_prob = 1.0
                        else:
                            m_max = stats.quantile_mmax
                            m_accept_prob = stats.quantile_accept_prob

                        p_hit = k / float(1 << tree_h)
                        sig_size = sig_size_pors_fp(h, args.d, k, m_max)

                    signer_work, expected_trials = signer_work_metric(
                        args=args,
                        family=family,
                        h=h,
                        k=k,
                        a=a,
                        tree_height=tree_h,
                        m_accept_prob=m_accept_prob,
                    )
                    if signer_work > args.signer_cap:
                        continue

                    forge_prob = fluhrer_dang_forge_prob(args.q, h, k, p_hit)
                    sec = security_bits_from_prob(forge_prob)
                    if sec < args.min_security_bits:
                        continue

                    out.append(
                        Candidate(
                            family=family,
                            h=h,
                            d=args.d,
                            k=k,
                            a=a,
                            q=args.q,
                            tree_height=tree_h,
                            m_max=m_max,
                            m_accept_prob=m_accept_prob,
                            m_expected_trials=expected_trials,
                            p_hit=p_hit,
                            sec_bits=sec,
                            forge_prob=forge_prob,
                            lambda_reuse=lam,
                            signer_work=signer_work,
                            sig_size=sig_size,
                            keygen_keccak_calls=calls,
                            keygen_70_s=keygen_70,
                            keygen_48_s=keygen_48,
                        )
                    )

    fam_rank = {"fors_c": 0, "pors_fp": 1}
    out.sort(key=lambda c: (c.sig_size, fam_rank.get(c.family, 9), c.signer_work, c.sec_bits))
    return out


def print_summary(cands: list[Candidate], args: argparse.Namespace) -> None:
    print("Constrained sweep (FORS+C / PORS+FP)")
    print(
        f"q={args.q}, d={args.d}, min_sec={args.min_security_bits} bits, "
        f"keygen<={args.keygen_max_s:.1f}s (70/48MHz), "
        f"signer_cap={args.signer_cap} ({args.signer_cap_mode}), family={args.family}"
    )
    print(
        f"search space: h=[{args.h_min},{args.h_max}], "
        f"k=[{args.k_min},{args.k_max}], a=[{args.a_min},{args.a_max}]"
    )
    if args.family in ("pors_fp", "all"):
        print(
            f"pors model: mmax_policy={args.pors_mmax_policy}, "
            f"samples={args.pors_samples}, quantile={args.pors_quantile:.4f}, seed={args.pors_seed}"
        )
    print()

    if not cands:
        print("No candidates found.")
        return

    print(
        "rank family   h d  k  a  th  mMax  sec_bits  sig_bytes  signer_work  "
        "keygen70s  keygen48s  lambda   asm_gas   tx_gas mode   q120 sigs  lambda120   q112 sigs  lambda112"
    )
    for i, c in enumerate(cands[: args.top], 1):
        sec_str = "inf" if math.isinf(c.sec_bits) else f"{c.sec_bits:.2f}"
        mmax_str = "-" if c.m_max is None else str(c.m_max)
        asm_gas = estimate_asm_verify_gas(
            family=c.family,
            h=c.h,
            d=c.d,
            k=c.k,
            a=c.a,
            tree_height=c.tree_height,
            m_max=c.m_max,
        )
        tx_gas, floor_dom = estimate_total_tx_gas(sig_size=c.sig_size, asm_verify_gas=asm_gas)
        tx_mode = "floor" if floor_dom else "std"
        b120 = _find_q_for_security_target(
            h=c.h,
            k=c.k,
            p_hit=c.p_hit,
            target_bits=120.0,
            q_start=args.q,
            q_max=args.q_budget_search_max,
        )
        b112 = _find_q_for_security_target(
            h=c.h,
            k=c.k,
            p_hit=c.p_hit,
            target_bits=112.0,
            q_start=args.q,
            q_max=args.q_budget_search_max,
        )
        print(
            f"{i:>4} {c.family:>7}  {c.h:>2} {c.d:>1} {c.k:>2} {c.a:>2} "
            f"{c.tree_height:>3} {mmax_str:>5}  {sec_str:>8}  {c.sig_size:>9}  "
            f"{c.signer_work:>11}  {c.keygen_70_s:>8.2f}  {c.keygen_48_s:>8.2f}  "
            f"{c.lambda_reuse:>6.3f}  {asm_gas:>8}  {tx_gas:>7} {tx_mode:>4}  "
            f"{_fmt_int_with_commas(b120.q_target):>10}  "
            f"{_fmt_lambda(b120.lambda_reuse):>9}  {_fmt_int_with_commas(b112.q_target):>10}  "
            f"{_fmt_lambda(b112.lambda_reuse):>9}"
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Constrained Fluhrer-Dang parameter sweep")
    p.add_argument("--family", choices=["fors_c", "pors_fp", "all"], default="all")
    p.add_argument("--q", type=int, default=1 << 20)
    p.add_argument("--d", type=int, default=2)
    p.add_argument("--h-min", type=int, default=12)
    p.add_argument("--h-max", type=int, default=30)
    p.add_argument("--k-min", type=int, default=5)
    p.add_argument("--k-max", type=int, default=24)
    p.add_argument("--a-min", type=int, default=8)
    p.add_argument("--a-max", type=int, default=30)
    p.add_argument("--min-security-bits", type=float, default=120.0)
    p.add_argument("--keygen-max-s", type=float, default=120.0)
    p.add_argument("--signer-cap-mode", choices=["blockstream", "k2a"], default="blockstream")
    p.add_argument("--signer-cap", type=int, default=None)

    p.add_argument("--pors-mmax-policy", choices=["quantile", "max"], default="quantile")
    p.add_argument("--pors-samples", type=int, default=2000)
    p.add_argument("--pors-quantile", type=float, default=0.999)
    p.add_argument("--pors-seed", type=int, default=1)
    p.add_argument(
        "--q-budget-search-max",
        type=int,
        default=1 << 32,
        help="Upper bound for q-target search used to print q120/q112 budgets.",
    )

    p.add_argument("--top", type=int, default=30)

    args = p.parse_args()

    if not (0.0 < args.pors_quantile <= 1.0):
        raise ValueError("--pors-quantile must be in (0, 1].")

    if args.signer_cap is None:
        if args.signer_cap_mode == "k2a":
            args.signer_cap = DEFAULT_SIGNER_CAP_K2A
        else:
            args.signer_cap = DEFAULT_SIGNER_CAP_BLOCKSTREAM

    return args


def main() -> None:
    args = parse_args()
    cands = sweep(args)
    print_summary(cands, args)


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# Findings / Notes (Blockstream-aligned sweep rationale)
# ---------------------------------------------------------------------------
# 1) Family coverage:
#    This script now supports both families in one place:
#      - FORS+C   (W+C + FORS+C)
#      - PORS+FP  (W+C + PORS+FP)
#    Use --family all to compare both directly under the same constraints.
#
# 2) Signer-cap modeling:
#    Default signer cap is Blockstream-aligned full signer hash-call workload,
#    not the legacy k*2^a proxy. Legacy mode remains available via:
#      --signer-cap-mode k2a
#
# 3) PORS+FP m_max / Octopus modeling:
#    For each (k, tree_height), Octopus auth-node counts are sampled by Monte
#    Carlo. m_max is then selected by policy:
#      - quantile: m_max = q-quantile count (default q=0.999)
#      - max:      m_max = observed max (no octopus-cap grind failures)
#    The selected m_max impacts both signature size and expected R-grind work.
#
# 4) Security objective:
#    The Fluhrer-Dang style reuse model is applied with family-specific p_hit:
#      - FORS+C:  p_hit = 2^-a
#      - PORS+FP: p_hit = k / 2^tree_height
#    where tree_height = ceil(log2(k * 2^a)).
#
# 5) Keygen remains separate:
#    keygen_keccak_calls() models one top-subtree root build only (one-time).
#    signer_cap models per-signature signing workload.
#
# 6) Reuse/security budget columns:
#    Output now includes:
#      - q120 sigs, lambda120: max signatures and expected reuse lambda at 120-bit floor
#      - q112 sigs, lambda112: max signatures and expected reuse lambda at 112-bit floor
#    computed with the same Fluhrer-Dang model by bracketing + binary search in q.
#
# 7) Gas columns:
#    Output now includes:
#      - asm_gas: estimated pure verifier compute gas for the asm implementation
#      - tx_gas:  estimated total tx gas using tx=max(21K+std_cd+asm, 21K+floor_cd)
#      - mode:    "floor" if calldata floor dominates, else "std"
#    The verify compute estimator is calibrated to measured C2/C4 (FORS+C) and
#    C1/C3 (PORS+FP) points from this repository.
