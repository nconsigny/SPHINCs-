# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SPHINCs- is a research prototype implementing post-quantum Ethereum accounts using lightweight SPHINCS+ variants (SPHINCs- C6–C11) and JARDÍN (FORS+C compact path). Supports JARDÍN hybrid accounts (ECDSA + SPHINCs-), stateless ERC-4337 accounts, and EIP-8141 frame transaction accounts (pure PQ). **Not audited, not production-safe.**

## Build and Test Commands

```bash
forge build                                          # compile all contracts
forge test                                           # run all tests
cd signer-wasm && cargo test --release -- --ignored  # Rust signer roundtrip (9/9 tests)
```

Python environment:
```bash
pip install eth-account eth-abi requests pycryptodome
```

## Architecture

### Shared Verifier Model

The SPHINCs- verifier is deployed once and shared by all accounts. Each account stores its own keys and calls the shared verifier with keys as arguments.

```
SPHINCs-Asm (deployed once, stateless, pure)
    ↑ verify(pkSeed, pkRoot, message, sig) → bool
    │
    ├── SphincsAccount (4337)       ← keys as immutables, passes to verifier
    └── FrameAccount (EIP-8141)     ← keys embedded in bytecode as PUSH32
```

### Contracts

| File | Purpose |
|---|---|
| `SPHINCs-C6Asm.sol` | Shared C6 verifier: h=24 w=16 l=32, verify=156K |
| `SPHINCs-C7Asm.sol` | Shared C7 verifier: h=24 w=8 l=43, verify=127K |
| `SPHINCs-C8Asm.sol` | Shared C8 verifier: h=20 w=16 l=32, verify=194K |
| `SPHINCs-C9Asm.sol` | Shared C9 verifier: h=20 w=8 l=43, verify=117K |
| `SPHINCs-C10Asm.sol` | Shared C10 verifier: h=18 w=8 l=43, verify=115K |
| `SPHINCs-C11Asm.sol` | Shared C11 verifier: h=16 w=8 l=43, verify=116K |
| `SphincsAccount.sol` | ERC-4337 hybrid account (keys in storage, rotatable) |
| `SphincsAccountFactory.sol` | Deploys accounts (shared verifier in constructor) |
| `SphincsFrameAccount.sol` | Solidity reference for EIP-8141 frame account |
| `JardinForsCVerifier.sol` | JARDÍN FORS+C-only verifier: k=26 a=5, verify=~51K |
| `JardinT0Verifier.sol` | JARDINERO Tier-0 verifier: plain-FORS + WOTS+C hypertree, verify=470K |
| `JardinAccount.sol` | JARDINERO hybrid ECDSA + ERC-4337: Type 1 (T0, primary) + Type 2 (FORS+C) + Type 3 (C11 optional recovery) |
| `JardinAccountFactory.sol` | Deploys JARDINERO accounts (ECDSA owner + T0 + FORS+C verifiers) |
| `JardinFrameAccount.sol` | Legacy C11-based EIP-8141 frame account |
| `JardineroFrameAccount.sol` | JARDINERO EIP-8141 frame account: pure PQ, T0 + FORS+C |

### Variants

All SPHINCs- variants use W+C_F+C, n=128-bit, d=2, domain-separated H_msg (160 bytes).

| Variant | h | a | k | w | swn | Sig | sign_h | Verify | Frame | 4337 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C6 | 24 | 16 | 8 | 16 | 240 | 3352 B | 5.7M | 156K | 232K | 333K | 128 |
| **C7** | **24** | **16** | **8** | **8** | **151** | **3704 B** | **4.3M** | **127K** | **210K** | **318K** | **128** |
| C8 | 20 | 13 | 12 | 16 | 162 | 3848 B | 1.4M | 194K | 271K | 377K | 128 |
| **C9** | **20** | **12** | **11** | **8** | **208** | **3816 B** | **1.3M** | **117K** | **195K** | **300K** | **112.6** |
| C10 | 18 | 11 | 13 | 8 | 205 | 4008 B | 609K | 115K | 203K | 308K | 104.5 |
| C11 | 16 | 11 | 13 | 8 | 203 | 3976 B | 292K | 116K | 202K | 308K | 86.1 |

### JARDÍN (Judicious Authentication from Random-subset Domain-separated Indexed Nodes)

Hybrid ECDSA + compact FORS+C account. Balanced Merkle tree of height h=7
commits Q_MAX=128 FORS+C instances per slot.

### JARDINERO (Tier-0 variant, onboarding-friendly)

T0 (`T0_W+C_h14_d7_a6_k39`) replaces C11 as the slot-registration path. Top-layer
XMSS has only 4 WOTS+C keypairs (h'=2), so onboarding keygen is ~40× faster
than C11 on hardware. C11 becomes an optional recovery path attached via
`attachC11Recovery()` post-deploy.

| Parameter | Value |
|---|---|
| n | 16 bytes (128-bit hash truncation) |
| h (total hypertree height) | 14 |
| d (layers) | 7 |
| h' (per-layer XMSS height) | 2 (4 leaves/layer) |
| a (FORS tree height) | 6 (64 leaves/tree) |
| k (FORS trees) | 39 |
| w (Winternitz) | 16 |
| l (WOTS chains) | 32 (no checksum — WOTS+C) |
| swn (WOTS+C target digit sum) | 240 |
| q_s_budget | 2^13 = 8,192 lifetime sigs @ 128-bit |
| Sig size | 8,220 B |
| H_msg domain separator | `0xFF..FE` (distinct from C11's `0xFF..FF`) |

```
JardinT0Verifier         JardinForsCVerifier           SPHINCs-C11Asm (optional)
    ↑ verify(...)             ↑ verifyForsC(...)            ↑ verify(...)
    │                         │                             │
    └─ Type 1 (ECDSA+T0) ─────┘── Type 2 (ECDSA+FORS+C)     └── Type 3 (ECDSA+C11 recovery)
                      │
                 JardinAccount (ERC-4337, hybrid)
                 ├── owner (ECDSA signer, rotatable)
                 ├── t0PkSeed, t0PkRoot (T0 identity)
                 ├── c11Verifier / c11PkSeed / c11PkRoot (zero until attached)
                 ├── slots: mapping(H(subPkSeed,subPkRoot) → 1)
                 ├── Type 1: T0 sig + register sub-key slot (or stateless fallback when sub=0)
                 ├── Type 2: FORS+C compact (requires registered slot)
                 └── Type 3: C11 recovery (requires attachC11Recovery self-call)
```

Measured gas (Sepolia via Candide + ethrex frame txs, 3×3 cycle each):

| Event | Sig | 4337 (Sepolia) | Frame (ethrex) |
|---|---|---|---|
| Type 1 (T0 + register) | 8,318 B / 8,253 B | **705K** | **650K** |
| Type 2 (FORS+C compact) | 2,663 B / 2,598 B | **168K** | **121K** |

T0 verify alone (assembly): **470K gas**. FORS+C verify alone: **51K gas**.

The ~55K/47K frame advantage is EntryPoint overhead we don't pay on ethrex.

FORS+C (unchanged from earlier JARDÍN): k=26, a=5, n=16B (128-bit). Balanced
Merkle h=7, Q_MAX=128. q encoded as 1-byte explicit field. FORS+C tolerates
r=2 at 105-bit. H_msg: 192-byte domain-separated hash
(seed||root||R||msg||counter||domain).

### Off-chain Components

- `script/signer.py` — Python signer (c2/c6/c7 variants)
- `script/jardin_signer.py` — JARDÍN FORS+C signer (balanced h=7 tree + FORS+C)
- `script/jardin_t0_signer.py` — JARDINERO T0 signer (plain FORS + WOTS+C hypertree)
- `script/jardin_userop.py` — legacy JARDÍN (C11-based) 4337 UserOp builder
- `script/jardin_t0_userop.py` — JARDINERO 4337 UserOp builder (Candide bundler)
- `script/jardin_frame_tx.py` — legacy JARDÍN (C11-based) EIP-8141 frame tx
- `script/jardinero_frame_tx.py` — JARDINERO EIP-8141 frame tx (ethrex)
- `script/deploy_jardin_frame.py` — Deploys hand-optimized frame proxy (works for both impls)
- `script/DeployJardineroSepolia.s.sol` — Forge deploy script for T0 + FORS+C + factory
- `signer-wasm/` — Rust WASM signer with BIP-39/44 key derivation

### Key Derivation

BIP-39 mnemonic → HMAC-SHA512 → SPHINCs- keys (quantum-safe path, independent from ECDSA).

### Gas Optimizations Applied

- Branchless Merkle swap: `mstore(xor(0x40, s), node)` (Solady pattern)
- SHL for power-of-2 multiplications: `shl(4, i)` instead of `mul(i, 16)`
- Hoisted loop-invariant chain address: `chainBase` computed once per chain
- Domain-separated H_msg: 160-byte hash prevents ThPair collision
- Frame account v2: keys embedded as PUSH32 (no SLOAD, saves 4.2K gas)

## Formal Verification (verity/)

Lean 4 model via Verity framework: 3 axioms (keccak CR), 20 theorems, 0 sorry.
`verity_contract` macro version gets Layer 1-2-3 compilation correctness proofs.
See `verity/README.md` for proof inventory.

## Foundry Config

- `via_ir = true`, `optimizer_runs = 200`
- `ffi = true` (for Python signer calls)
- Deployed on Sepolia (chain 11155111) and ethrex (chain 1729)
