# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SPHINCs- is a research prototype for lightweight SPHINCS+ variants on Ethereum. Three families of on-chain verifiers live here:

1. **C-series** (C7, C11 in `src/`; C6/C8/C9/C10 in `legacy/src/`) — stateless WOTS+C / FORS+C (ePrint 2025/2203), n=128. Signature-count cap = 2^h (C7 → 2²⁴, C11 → 2¹⁶); security degrades with N as shown in the variants table in the README.
2. **C12** (`src/SPHINCs-C12Asm.sol`) — plain SPHINCS+ (SPX) variant of the SPHINCs- family, with the JARDIN 32-byte ADRS kernel + keccak256 truncated to 16 B. h=20, d=5, a=7, k=20, w=8, l=45. 6,512-B sig, ~276 K verify gas. Cross-referenced by the JARDIN repo as `JardinSpxVerifier`.
3. **SLH-DSA-128-24** — NIST SP 800-230 parameter set (d=1, h=22, a=24, k=6, w=4). Two variants:
   - FIPS 205 bit-exact SHA-2 (`src/SLH-DSA-SHA2-128-24verifier.sol`), uses the SHA-256 precompile at 0x02.
   - JARDIN-convention Keccak twin (`src/SLH-DSA-keccak-128-24verifier.sol`), uses the native `keccak256` opcode.

Accounts present in this repo use the C-series: `SphincsAccount` (ERC-4337), `SphincsAccountFactory`, `SphincsFrameAccount` (EIP-8141). The JARDIN hybrid-account stack (ECDSA + SPHINCs-) lives in the separate [nconsigny/JARDIN](https://github.com/nconsigny/JARDIN) repo.

**Not audited, not production-safe.**

## Build and Test Commands

```bash
forge build                                             # compile all contracts
forge test                                              # run all forge tests
cd signer-wasm && cargo test --release -- --ignored     # Rust C-series signer (9/9)

# SLH-DSA-128-24 fast C signers (one-time build; ~11 min per NIST-params sign):
(cd signers/sphincsplus-128-24  && make)
(cd signers/jardin-keccak-128-24 && make)

# Forge FFI end-to-end tests (first run triggers a real sign; cache hits after):
forge test --match-contract SLH_DSA_SHA2_128_24_Test   -vv
forge test --match-contract SLH_DSA_Keccak_128_24_Test -vv
```

Python env: `pip install eth-account eth-abi requests pycryptodome`.

## Architecture

### Shared Verifier Model

Every verifier is deployed once as a stateless pure contract and shared by all accounts. Accounts store their own keys and pass them into the verifier on each call.

```
<verifier> (deployed once, stateless, pure)
    ↑ verify(pkSeed, pkRoot, message, sig) → bool
    │
    ├── SphincsAccount        (ERC-4337, keys as immutables)
    └── SphincsFrameAccount   (EIP-8141, keys embedded in bytecode via PUSH32)
```

The **C-series, C12, and SLH-DSA-Keccak** verifiers all share the JARDIN kernel: one 32-byte ADRS layout and the `keccak(seed32 ‖ adrs32 ‖ inputs)` tweakable-hash shape (see `script/jardin_primitives.py`). A device port covers those four with a single `sphincs_th*` implementation. **SLH-DSA-SHA2-128-24 is the outlier** — it uses FIPS 205's 22-byte compressed ADRSc + SHA-256 with the nested MGF1 Hmsg, so it needs its own primitive set.

### Current contracts (`src/`)

| File | Purpose |
|---|---|
| `SPHINCs-C7Asm.sol` | C-series verifier, stateless, n=128, h=24 d=2 a=16 k=8 w=8. 3,704-B sig, ~127 K verify |
| `SPHINCs-C11Asm.sol` | C-series verifier, stateless, n=128, h=16 d=2 a=11 k=13 w=8. 3,976-B sig, ~116 K verify |
| `SphincsAccount.sol` | ERC-4337 hybrid account (ECDSA + SPHINCs- C-series), verifier pluggable via immutable |
| `SphincsAccountFactory.sol` | CREATE2 factory for `SphincsAccount` |
| `SphincsFrameAccount.sol` | EIP-8141 pure-PQ frame account; keys embedded in bytecode (no SLOAD) |
| `SPHINCs-C12Asm.sol` | C12 — plain SPHINCS+ verifier with JARDIN 32-byte ADRS. 6,512-B sig, ~276 K verify |
| `SLH-DSA-SHA2-128-24verifier.sol` | FIPS 205 bit-exact SLH-DSA-SHA2-128-24 verifier (SHA-256 precompile) |
| `SLH-DSA-keccak-128-24verifier.sol` | JARDIN-convention SLH-DSA-Keccak-128-24 verifier (keccak opcode) |
| `SLH-DSA-SHA2-128-24-Diagnostic.sol` | Debug tool used to bisect the SHA-2 verifier during development |

### Frozen variants (`legacy/`)

Prior C-series verifiers (C6, C8, C9, C10) kept for benchmark reproducibility. Same 32-byte ADRS kernel, different parameters. See `legacy/README.md`.

| Variant | h | a | k | w | swn | Sig | sign_h | Verify | Frame | 4337 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C6 | 24 | 16 | 8 | 16 | 240 | 3352 B | 5.7M | 156K | 232K | 333K | 128 |
| **C7** | **24** | **16** | **8** | **8** | **151** | **3704 B** | **4.3M** | **127K** | **210K** | **318K** | **128** |
| C8 | 20 | 13 | 12 | 16 | 162 | 3848 B | 1.4M | 194K | 271K | 377K | 128 |
| C9 | 20 | 12 | 11 | 8 | 208 | 3816 B | 1.3M | 117K | 195K | 300K | 112.6 |
| C10 | 18 | 11 | 13 | 8 | 205 | 4008 B | 609K | 115K | 203K | 308K | 104.5 |
| **C11** | **16** | **11** | **13** | **8** | **203** | **3976 B** | **292K** | **116K** | **202K** | **308K** | **86.1** |

## SLH-DSA-128-24

NIST SP 800-230 (April 2026 IPD) parameter set with a hard 2^24 signature limit per key. Parameters: n=16, h=22, d=1 (single XMSS tree), h'=22, a=24, k=6, w=4, m=21. Signature size 3,856 B (same for both hash variants).

- **SHA-2 variant** (`SLH-DSA-SHA2-128-24verifier.sol`): FIPS 205 bit-exact. 22-byte compressed ADRSc, nested Hmsg = `MGF1-SHA-256(R‖seed‖SHA-256(R‖seed‖root‖M), 21)`, LSB-first-within-bytes digest parsing (industry SPHINCS+ convention). Every F / H / T is a SHA-256 precompile (0x02) staticcall.
- **Keccak variant** (`SLH-DSA-keccak-128-24verifier.sol`): JARDIN-family twin. 32-byte full JARDIN ADRS (`layer4‖tree8‖type4‖kp4‖ci4‖cp4‖ha4`), one-shot Hmsg = `keccak(seed‖root‖R‖msg‖0xFF..FB)`, LSB-first digest parsing on the 256-bit keccak output (not byte-wise), LSB-first-within-128-bit WOTS `base_w`. Every F / H / T is a native `keccak256` opcode.

**Hash-call counts** (both variants, same tree shape):

| Step | Operations | Calls |
|---|---|---:|
| Keygen — 2^22-leaf XMSS | leaves × (68 WOTS chains × 3 F + 1 T_l) + 2^22 − 1 H | ~864 M |
| Sign — FORS (6 × 2^24 leaves) | 6 × (leaves + internal + 1 T_k) | ~201 M |
| Sign — XMSS tree-hash pass (auth path) | same as keygen | ~864 M |
| Sign — WOTS on FORS-pk | 68 chains × ~1.5 F avg | ~100 |
| **Total keygen + sign** | | **≈ 1.93 × 10⁹** |

**Measured on-chain verify gas** (Sepolia top-level tx with 3,872-B calldata):
- SHA-2 variant: 225,642 gas (pure assembly ~142 K)
- Keccak variant: 177,910 gas (pure assembly ~94 K) — ~21 % cheaper at tx level, ~34 % at assembly level.

## Off-chain Components

### C-series signers

- `script/signer.py` — Python SPHINCs- C-series signer (C6–C11 all supported; slow, ~30 s per C6 sig)
- `signer-wasm/` — Rust/WASM C-series signer with BIP-39/44 key derivation

### C12 (plain SPHINCS+) signer

- `script/jardin_spx_signer.py` — Python signer for C12 (plain SPHINCS+, h=20, d=5, w=8). Self-contained; uses `jardin_primitives.py` for ADRS + tweakable hashes. Name kept as `jardin_spx_signer.py` because the same file is shared with the JARDIN repo's hybrid-account stack.

### SLH-DSA-128-24 signers

- `script/slh_dsa_sha2_128_24_signer.py`, `script/slh_dsa_keccak_128_24_signer.py` — pure-Python reference signers (very slow: ~hours at NIST params; use `--height N --a N` overrides for dev iteration).
- `signers/sphincsplus-128-24/` — fork of sphincs/sphincsplus ref with a `params-*-128-24.h` header and w=4 support. ~11 min for a full NIST-params sign in pure C.
- `signers/jardin-keccak-128-24/` — separate C fork for the Keccak variant. Adds a ~70 LOC minimal keccak256 (legacy 0x01 padding, Ethereum-flavour), a 32-byte JARDIN ADRS `address.c`, bit-level LSB-first digest-to-indices, and LSB-first-within-128-bit WOTS `base_w`.
- `script/slh_dsa_sha2_128_24_fast_signer.py`, `script/slh_dsa_keccak_128_24_fast_signer.py` — Python wrappers that derive seeds via JARDIN HMAC-SHA-512, invoke the C binary, cache the result on disk. Used by the Forge FFI tests.
- `signers/*/crosscheck.py` — Python-vs-C cross-validation at arbitrary h/a.

### Deploy scripts

- `script/DeploySlhDsa128_24Sepolia.s.sol` — deploys both SLH-DSA-128-24 verifiers to Sepolia.
- `legacy/script/DeploySepolia.s.sol` — deploys a C-series shared verifier + `SphincsAccountFactory`.

### Key derivation (C-series)

BIP-39 mnemonic → HMAC-SHA512("sphincs-c6-v1", seed) → SPHINCs- keys (quantum-safe path). ECDSA derived via BIP-32 m/44'/60'/0'/0/0 (independent from the SPHINCs- path).

## Gas Optimizations Applied

- Branchless Merkle swap: `mstore(xor(0x40, s), node)` (Solady pattern) — used in the 32-byte-aligned C-series, C12, and SLH-DSA-Keccak verifiers. The SLH-DSA SHA-2 verifier has a 16-byte-aligned L/R layout that REQUIRES L-first-then-R order; see the `switch and(pathIdx, 1)` blocks.
- SHL for power-of-2 multiplications (`shl(4, i)` instead of `mul(i, 16)`)
- Hoisted loop-invariant chain address
- Domain-separated H_msg (prevents cross-variant collisions)
- Frame-account v2: keys embedded as PUSH32 (no SLOAD, saves ~4.2 K gas)

## Formal Verification (`verity/`)

Lean 4 model via Verity framework: 3 axioms (keccak CR), 20 theorems, 0 sorry. `verity_contract` macro version has Layer 1-2-3 compilation correctness proofs. See `verity/README.md` for proof inventory.

## Foundry Config

- `via_ir = true`, `optimizer_runs = 200`
- `ffi = true` (for Python signer calls)
- Deployed on Sepolia (chain 11155111). Legacy ethrex (chain 1729) deployments for the frame-tx path.
