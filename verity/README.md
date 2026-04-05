# Formal Verification — SPHINCS+ C6

Lean 4 formal model and [Verity](https://github.com/Th0rgal/verity)-compiled EVM bytecode for the C6 verifier (FORS+C h=24, d=2, a=16, k=8, w=16).

## Status

**3 axioms, 20 theorems, 0 sorry.**

The 3 axioms are irreducible keccak256 cryptographic assumptions (`th_collision_resistant`, `th_domain_separated`, `thPair_collision_resistant`). Everything else is machine-checked by Lean 4.

## Structure

```
verity/
├── SphincsC6/                ← Pure Lean functional model
│   ├── Types.lean            ← Parameters, ADRS, signature types
│   ├── Hash.lean             ← Keccak primitives + 3 crypto axioms
│   ├── WotsC.lean            ← WOTS+C w=16: digit extraction, chain verify, PK compress
│   ├── ForsC.lean            ← FORS+C: forced-zero, tree verify, root compress
│   ├── Hypertree.lean        ← D=2 layers: Merkle auth path, layer composition
│   ├── Contract.lean         ← Full verify function + proven security properties
│   ├── Spec.lean             ← Parameter consistency specs
│   └── Proofs/
│       └── Correctness.lean  ← 14 theorems: binding, roundtrip, soundness
│
├── SphincsC6Full/            ← Manual CompilationModel (Verity EDSL, no oracle)
│   ├── Contract.lean         ← Full verification in Stmt/Expr DSL
│   ├── Spec.lean             ← Function specs (verify_spec, getPkSeed_spec)
│   ├── Invariants.lean       ← State immutability, key preservation
│   └── Proofs/
│       └── Basic.lean        ← Spec satisfaction proofs
│
├── SphincsC6V/               ← verity_contract macro (full Layer 1 proofs)
│   └── SphincsC6V.lean       ← Memory-as-state pattern for forEach loops
│
├── artifacts/                ← Verity-compiled Yul
│   ├── SphincsC6Full.yul     ← From manual CompilationModel
│   └── SphincsC6V.yul        ← From verity_contract macro
│
└── external-libs/
    └── SphincsC6Verify.yul   ← Linked oracle (used by SphincsC6Full only)
```

## Three Verification Tiers

| Tier | Source | Formal guarantee | Gas (EOA) |
|---|---|---|---|
| Hand-optimized ASM | `src/SPHINCs-C6Asm.sol` | Differential testing | 234K |
| Manual CompilationModel | `SphincsC6Full/` | Verity Layer 2-3 | 255K |
| **`verity_contract` macro** | **`SphincsC6V/`** | **Verity Layer 1-2-3** | **283K** |

## Proven Properties

| Theorem | What it proves |
|---|---|
| `wots_chain_roundtrip` | sign(sk, digit) then verify(σ, digit) = pk |
| `chain_binding` | WOTS chain injective (induction on steps via CR) |
| `merkle_node_binding` | ThPair same output → same (left, right) |
| `merkle_level_binding` | Auth path level binding (handles left/right ordering) |
| `leaf_binding` | Th injective (leaf preimage commitment) |
| `fors_leaf_binding` | FORS leaf secret binding |
| `wots_c_digit_sum` | Valid sig → digit sum = 240 |
| `fors_c_forced_zero` | Valid sig → last FORS index = 0 |
| `verify_soundness` | verify=true → computed root = pkRoot |
| `param_consistency` | SIG_SIZE=3352, H=D×SUBTREE_H, K×A=128 |

## Build

```bash
# Standalone Lean model (no Verity framework needed)
cd verity && lake build

# With Verity framework (for compilation to Yul)
git clone https://github.com/Th0rgal/verity.git verity-framework
cd verity-framework && lake update
# Copy contracts and compile:
lake exe verity-compiler --module Contracts.SphincsC6V.SphincsC6V -o artifacts/yul
```

## References

- [ePrint 2025/2203](https://eprint.iacr.org/2025/2203) — Blockstream SPHINCS+ (WOTS+C, FORS+C security proofs)
- [SPHINCS+ R3.1 Spec](https://sphincs.org/data/sphincs+-r3.1-specification.pdf) — Hash function assumptions (§3), Merkle binding (§6)
- [Verity](https://github.com/Th0rgal/verity) — Lean 4 → EVM formally verified smart contracts
