# WOTS+C OTS Verifier — Verity (Lean 4) Implementation

Formally verified one-time signature verifier written directly in the [Verity](https://github.com/Th0rgal/verity/) framework.

## Setup

```bash
# Clone Verity framework
git clone https://github.com/Th0rgal/verity.git verity-framework
cd verity-framework

# Copy contract files
cp -r ../Contracts/WotsOtsVerifier Contracts/
cp ../external-libs/WotsChainVerify.yul examples/external-libs/

# Add to lakefile.lean (in the Contracts lean_lib globs):
#   .andSubmodules `Contracts.WotsOtsVerifier,

# Build (type-checks all proofs)
lake build Contracts.WotsOtsVerifier

# Compile to Yul (add wotsOtsVerifierSpec to Contracts/Specs.lean first)
lake exe verity-compiler --link examples/external-libs/WotsChainVerify.yul -o artifacts/yul
```

## Architecture

Same two-layer pattern as Verity's CryptoHash/Poseidon example:

1. **Lean layer** (formally verified): Storage management, used-flag check/set via `bitAnd`/`bitOr`, `require` guards. Chain verifier modeled as `callOracle` (opaque in proofs).

2. **Linked Yul layer** (trusted, gas-optimized): `wotsChainVerify(sigOffset, sigLen, message, seed) -> computedPk`. Contains the 32 chain hash loops + PK compression. Linked at compile time via `--link`.

## Files

| File | Purpose |
|------|---------|
| `Contracts/WotsOtsVerifier/Contract.lean` | Contract monad: storage, used-flag, `callOracle` for chain verification |
| `Contracts/WotsOtsVerifier/Spec.lean` | Formal specifications |
| `Contracts/WotsOtsVerifier/Invariants.lean` | Wellformedness invariants |
| `Contracts/WotsOtsVerifier/Proofs/Basic.lean` | 8 theorems (6 proven, 2 sorry) |
| `Contracts/WotsOtsVerifier/CompilationModel.lean` | Manual CompilationModel with `Expr.externalCall` |
| `external-libs/WotsChainVerify.yul` | Linked Yul: 32 chain completions + PK compression |

## Proven Theorems

- `verify_success_implies_spent` — successful verify marks key as spent
- `spent_key_fails_check` — spent key causes require failure
- `at_most_one_verify` — at most one successful verification per lifetime
- `verify_preserves_seed` — slot 0 never modified
- `used_flag_monotone` — spent + success is impossible (contradiction)
- `setup_stores_seed` / `setup_stores_pkHash` — constructor correctness

## Parameters

w=16, n=128 bits, l=32, targetSum=240, z=0, sig=516 bytes.

Reference: ePrint 2025/2203 (Blockstream SPHINCS+C)
