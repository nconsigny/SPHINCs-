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
| `JardinForsCVerifier.sol` | JARDÍN FORS+C-only verifier: k=26 a=5, variable h ∈ [2,8] (inferred from sig length), verify ≈ 50.6K + 300×h gas |
| `JardinSpxVerifier.sol` | JARDÍN plain-SPHINCS+ (SPX) verifier: h=20 d=5 a=7 k=20 w=8 l=45, 6512B sig, verify=278K |
| `JardinT0Verifier.sol` | (Legacy alternative) JARDINERO Tier-0 verifier: plain-FORS + WOTS+C hypertree, verify=470K |
| `JardinAccount.sol` | JARDÍN hybrid ECDSA + ERC-4337: Type 1 (SPX, primary) + Type 2 (FORS+C) + Type 3 (C11 optional recovery) |
| `JardinAccountFactory.sol` | Deploys JARDÍN accounts (ECDSA owner + SPX + FORS+C verifiers) |
| `JardinFrameAccount.sol` | Legacy C11-based EIP-8141 frame account |
| `JardineroFrameAccount.sol` | JARDÍN EIP-8141 frame account: pure PQ, SPX + FORS+C |

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

Hybrid ECDSA + plain-SPHINCS+ registration path + compact FORS+C compact
path. Balanced Merkle tree of height h=7 commits Q_MAX=128 FORS+C instances
per registered slot.

### Current registration path: plain SPHINCS+ (SPX)

`JardinSpxVerifier` is the default Type 1 verifier baked into
`JardinAccount` / `JardineroFrameAccount`. It implements standard SPHINCS+
(not WOTS+C — plain WOTS+ checksum) with the keccak256 hash primitive
truncated to 128 bits.

| Parameter | Value |
|---|---|
| n | 16 bytes (128-bit keccak truncation) |
| h (total hypertree height) | 20 |
| d (layers) | 5 |
| h' (per-layer XMSS height) | 4 (16 leaves/layer) |
| a (FORS tree height) | 7 (128 leaves/tree) |
| k (FORS trees) | 20 |
| w (Winternitz) | 8 |
| l1, l2, l (WOTS chains) | 42, 3, 45 (plain WOTS+ checksum) |
| R (per-sig randomness) | 32 bytes |
| ADRS | 12 bytes (compact, big-endian fields) |
| Hmsg | keccak256(R ‖ PKseed ‖ PKroot ‖ M), full 256-bit output |
| Sig size | 6,512 B (R 32 + FORS 2,560 + hypertree 3,920) |
| Signing cost | ~36.6K keccak calls |
| Security @ 2^11 sigs | 128.0 bits (flat to 127.8 at 2^14) |

```
JardinSpxVerifier        JardinForsCVerifier           SPHINCs-C11Asm (optional)
    ↑ verify(...)             ↑ verifyForsC(...)            ↑ verify(...)
    │                         │                             │
    └─ Type 1 (ECDSA+SPX) ────┘── Type 2 (ECDSA+FORS+C)     └── Type 3 (ECDSA+C11 recovery)
                      │
                 JardinAccount (ERC-4337, hybrid)
                 ├── owner (ECDSA signer, rotatable)
                 ├── spxPkSeed, spxPkRoot (SPX identity, rotatable)
                 ├── c11Verifier / c11PkSeed / c11PkRoot (zero until attached)
                 ├── slots: mapping(H(subPkSeed,subPkRoot) → 1)
                 ├── Type 1: SPX sig + register sub-key slot (or stateless fallback when sub=0)
                 ├── Type 2: FORS+C compact (requires registered slot)
                 └── Type 3: C11 recovery (requires attachC11Recovery self-call)
```

Measured gas (Sepolia via Candide + ethrex frame txs, 3×3 cycle each):

| Event | Sig | 4337 (Sepolia) | Frame (ethrex) |
|---|---|---|---|
| Type 1 (SPX + register) | 6,610 B / 6,545 B | **~1.1 mETH avg** (actualGasCost) | **416K gas** |
| Type 2 (FORS+C compact) | 2,663 B / 2,598 B | **~0.55 mETH avg** (actualGasCost) | **121K gas** |

SPX verify alone (assembly): **278K gas** compute; **401K on-chain** (4337
Sepolia), dominated by calldata floor (6512·64 = 416,768 gas). FORS+C verify
alone: **51K gas**.

### Legacy registration variants

`JardinT0Verifier` (T0: `T0_W+C_h14_d7_a6_k39`) and C11 both ship in
`src/` but are no longer wired into the default account: T0 was an earlier
onboarding attempt, and C11 now lives as an optional break-glass recovery
path attached per-account via `attachC11Recovery()`.

FORS+C (unchanged params): k=26, a=5, n=16B (128-bit). q encoded as 1-byte
explicit field. FORS+C tolerates r=2 at 105-bit. H_msg: 192-byte domain-
separated hash (seed||root||R||msg||counter||domain).

Variable outer-Merkle height: h ∈ [2, 8] (Q_MAX = 2^h). Inferred from sig
length: `h = (len - 2453) / 16`, revert unless `2 ≤ h ≤ 8` and length is
16-aligned. No extra wire byte. A single deployed verifier accepts Type 2
sigs from slots of any supported h. Because `forscVerifier` is immutable on
`JardinAccount`, existing accounts stay bound to whichever verifier was
baked into their factory; new accounts created via the variable-h factory
get the flexibility. Deployment addresses below.

### Off-chain Components

- `script/signer.py` — Python signer (c2/c6/c7 variants)
- `script/jardin_signer.py` — JARDÍN FORS+C signer (balanced h=7 tree + FORS+C)
- `script/jardin_spx_signer.py` — JARDÍN plain-SPHINCS+ signer (current registration path)
- `script/jardin_t0_signer.py` — Legacy JARDINERO T0 signer
- `script/jardin_userop.py` — Legacy JARDÍN (C11-based) 4337 UserOp builder
- `script/jardin_spx_userop.py` — JARDÍN SPX 4337 UserOp builder (Candide bundler)
- `script/jardin_t0_userop.py` — Legacy JARDINERO T0 4337 UserOp builder
- `script/jardin_frame_tx.py` — Legacy JARDÍN (C11-based) EIP-8141 frame tx
- `script/jardinero_frame_tx.py` — JARDÍN SPX EIP-8141 frame tx (ethrex)
- `script/deploy_jardin_frame.py` — Deploys hand-optimized frame proxy (agnostic to which primary verifier lives in slot 0; flags: `--verifier` with legacy `--spx`/`--c11` aliases)
- `script/DeployJardineroSepolia.s.sol` — Forge deploy script for SPX + FORS+C + factory
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
