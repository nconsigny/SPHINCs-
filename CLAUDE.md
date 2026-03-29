# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SPHINCs- is a research prototype implementing hybrid ECDSA + SPHINCS+ ERC-4337 smart accounts for Ethereum. It provides post-quantum signature verification on-chain using hand-optimized Yul/assembly verifiers. **Not audited, not production-safe.**

## Build and Test Commands

```bash
forge build                                          # compile all contracts (uses via_ir + optimizer)
forge test                                           # run all tests
forge test --match-contract AsmBenchmark -vv         # gas benchmarks (Solidity vs Assembly)
forge test --match-contract E2EVerification -vv      # end-to-end with Python FFI signer
forge test --match-test test_C2_E2E -vv              # single test
forge test --match-contract GasBenchmark -vv         # per-component gas costs
forge test --match-contract SecurityDecay -vv        # security decay tables
```

FFI is enabled (`ffi = true` in foundry.toml) — E2EVerification tests call `python3 script/signer.py` via `vm.ffi()`.

Python environment (needed for FFI tests and UserOp scripts):
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install eth-account eth-abi requests pycryptodome
```

## Architecture

### Signature Flow

UserOp signature = `abi.encode(ecdsaSig[65], sphincsSig[3740-4296])`. Both ECDSA and SPHINCS+ must verify. The SPHINCS+ verifier is a separate contract (one per user) storing `pkSeed` and `pkRoot`.

### Contract Layers

**Account layer:**
- `SphincsAccount` — ERC-4337 `BaseAccount` with dual signature validation (ECDSA recovery + `verifier.staticcall`)
- `SphincsAccountFactory` — CREATE2 factory deploying per-user verifier + account in one tx. Supports variants 2/3/4.

**Cryptographic primitives (libraries):**
- `TweakableHash` — Core hash: `keccak256(seed || adrs || input)` truncated to 128-bit. ADRS is a 32-byte tweak encoding layer/tree/type/position.
- `WotsPlusC` — WOTS+C: checksum-less WOTS with grinding (nonce `count` enforces fixed digit sum)
- `ForsPlusC` — FORS+C: last-tree forced-zero grinding (omits one auth path)
- `PorsFP` — PORS with Forced Pruning: single Merkle tree + Octopus-compressed auth sets

**Verifier contracts (one pair per variant):**

| File | Variant | Scheme | Sig bytes |
|---|---|---|---|
| `SphincsWcFc18` / `Asm` | C2 | WOTS+C + FORS+C, h=18 d=2 | 4040 |
| `SphincsWcPfp18` / `Asm` | C1 | WOTS+C + PORS+FP, h=18 d=2 | 4296 |
| `SphincsWcPfp27` / `Asm` | C3 | WOTS+C + PORS+FP, h=27 d=3 | 4188 |
| `SphincsWcFc30` / `Asm` | C4 | WOTS+C + FORS+C, h=30 d=3 | 3740 |

Each variant has a Solidity reference (`SphincsWc*.sol`) and an assembly-optimized version (`SphincsWc*Asm.sol`). The Asm versions use a fixed memory layout (no arrays, no free pointer) and inline all hash operations. Only Asm versions are used in production (via the factory).

`SecurityAnalysis` — On-chain library for signature reuse decay estimation (birthday-bound analysis).

### Python Off-chain Components (`script/`)

- `signer.py` — Reference SPHINCS+ signer. Generates keypairs, signs messages for all variants. Called via FFI from Foundry tests. Supports `c1`/`c2`/`c3`/`c4`.
- `send_userop.py` — ERC-4337 UserOp builder. Derives SPHINCS+ keys from ECDSA private key, constructs and submits hybrid-signed UserOps to Sepolia.
- `sweep_d2_fluhrer_dang.py` — Parameter sweep for Fluhrer-Dang security analysis.

### Key Parameters (n=128 bits throughout)

All variants use: `W=16`, `L=32`, `LEN1=32`, `TARGET_SUM=240`, `Z=0`, `N=16 bytes`. The differences are in hypertree height (`h`), depth (`d`), FORS/PORS tree count (`k`), and tree height (`a`).

## Foundry Config Notes

- `via_ir = true` — required for deep stack in Solidity verifiers
- `optimizer_runs = 200`
- Remappings: `account-abstraction/` → `lib/account-abstraction/contracts/`, `@openzeppelin/contracts/` → `lib/openzeppelin-contracts/contracts/`
- Deployed on Sepolia (chain ID 11155111)
