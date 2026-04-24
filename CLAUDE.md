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

### Current contracts (`src/`)

| File | Purpose |
|---|---|
| `JardinSpxVerifier.sol` | JARDÍN plain-SPHINCS+ (SPX) registration verifier: h=20 d=5 a=7 k=20 w=8 l=45, 6512B sig, 32-byte JARDIN ADRS, verify ~276K |
| `JardinForsPlainVerifier.sol` | JARDÍN plain-FORS compact-path verifier: k=32 a=4, variable h ∈ [2,8] (inferred from sig length), verify ~60K |
| `JardinAccount.sol` | JARDÍN hybrid ECDSA + ERC-4337: Type 1 (SPX) + Type 2 (plain-FORS) + Type 3 (C11 optional recovery) |
| `JardinAccountFactory.sol` | Deploys JARDÍN accounts (SPX + plain-FORS wired as immutables) |
| `JardineroFrameAccount.sol` | JARDÍN EIP-8141 frame account: pure PQ, SPX + plain-FORS |

All three verifiers share one ADRS layout (32-byte, JARDIN family) and one
set of tweakable-hash primitives (see `script/jardin_primitives.py`). A
single device `sphincs_th*` implementation services every current path.

### Frozen variants (`legacy/`)

Prior verifiers / accounts / signers (SPHINCs- C6–C11, `SphincsAccount*`,
`JardinT0Verifier`, `JardinForsCVerifier`, `JardinFrameAccount`, their
off-chain signers and older deploy scripts) live under `legacy/{src,script,test}/`
with git history preserved. They use the same 32-byte ADRS and same tweakable
hash as the current stack, just different scheme parameters. See
`legacy/README.md` for the inventory.

### Legacy SPHINCs- variants (in `legacy/src/`)

Reference values for the stateless C-series (WOTS+C + FORS+C, n=128-bit, d=2,
domain-separated H_msg 160 bytes). Kept for benchmark reproducibility; no
longer part of the default stack.

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
JardinSpxVerifier        JardinForsPlainVerifier       SPHINCs-C11Asm (optional)
    ↑ verify(...)             ↑ verifyForsPlain(...)        ↑ verify(...)
    │                         │                             │
    └─ Type 1 (ECDSA+SPX) ────┘── Type 2 (ECDSA+plainFORS)  └── Type 3 (ECDSA+C11 recovery)
                      │
                 JardinAccount (ERC-4337, hybrid)
                 ├── owner (ECDSA signer, rotatable)
                 ├── spxPkSeed, spxPkRoot (SPX identity, rotatable)
                 ├── c11Verifier / c11PkSeed / c11PkRoot (zero until attached)
                 ├── slots: mapping(H(subPkSeed,subPkRoot) → 1)
                 ├── Type 1: SPX sig + register sub-key slot (or stateless fallback when sub=0)
                 ├── Type 2: plain-FORS compact (k=32, a=4, variable h ∈ [2,8]; requires registered slot)
                 └── Type 3: C11 recovery (requires attachC11Recovery self-call)
```

SPX parameters (plain SPHINCS+, registration path):
- 32-byte JARDIN ADRS (`layer(4)‖tree(8)‖type(4)‖kp(4)‖ci(4)‖cp(4)‖ha(4)`)
- Hash inputs: F = 96 B, H = 128 B, T_l = 1504 B, T_k = 704 B
- H_msg = keccak(seed‖root‖R‖msg‖0xFF..FC), 160 B
- LSB-first digest parsing; SLH-DSA base_w checksum (MSB-first 3-bit chunks)
- Sig size 6512 B, verify gas ~276K, sign ~36.6K keccak

Plain-FORS compact-path parameters:
- k=32 FORS trees, a=4 tree height (16 leaves/tree)
- Sig length = 2593 + 16·h bytes (2625 B at h=2 … 2721 B at h=8; 2657 B at h=4)
- No counter grinding, no forced-zero last tree (all k trees revealed with sk+auth)
- H_msg = keccak256(seed‖root‖R‖msg‖0xFF..FD), 160 B
- Verify gas: ~60K (plain FORS has no WOTS chains)

Domain separators (all written as 32-byte big-endian in H_msg's trailing word):
C11 `0xFF..FF` · T0 `0xFF..FE` · plain-FORS `0xFF..FD` · SPX `0xFF..FC` ·
FORS+C `0xFF..FF` + counter (structurally distinct — 192 B H_msg).

Measured gas (3×3 cycle, SPX registration + plain-FORS compact):

| Event | Sig | 4337 (Sepolia) | Frame (ethrex) |
|---|---|---|---|
| Type 1 (SPX + register) | 6,610 B / 6,545 B | ~1.1 mETH (actualGasCost) | 416K gas |
| Type 2 (plain-FORS, h=4) | ~2,760 B / 2,657 B | TBD | ~95K gas (projected: ~60K verify + frame overhead) |

SPX verify alone: **278K gas** compute; **401K on-chain** (calldata floor at
6512·64 = 416.8K). Plain-FORS verify alone: **~60K gas**.

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

Shared primitive library:
- `script/jardin_primitives.py` — keccak256, 32-byte `make_adrs`, `th / th_pair / th_multi`, ADRS type constants. Imported by both active signers.

Current signers + UserOp / frame-tx builders:
- `script/jardin_spx_signer.py` — plain-SPHINCS+ (registration path)
- `script/jardin_fors_plain_signer.py` — plain-FORS (compact path, variable h)
- `script/jardin_spx_userop.py` — 4337 UserOp builder (SPX + plain-FORS via Candide)
- `script/jardinero_frame_tx.py` — EIP-8141 frame tx builder (ethrex)
- `script/deploy_jardin_frame.py` — Hand-optimized frame proxy deployer (`--verifier` flag with legacy `--spx`/`--c11` aliases)
- `script/DeployJardineroSepolia.s.sol` — Forge deploy script for SPX + plain-FORS + factory
- `signer-wasm/` — Rust WASM signer with BIP-39/44 key derivation (targets the current stack)

SLH-DSA-128-24 experimental signers (NIST SP 800-230 parameter set, research prototype):
- `src/SLH-DSA-SHA2-128-24verifier.sol` — FIPS 205 bit-exact SHA-2 verifier (uses the SHA-256 precompile)
- `src/SLH-DSA-keccak-128-24verifier.sol` — JARDIN-style Keccak twin of the above (keccak opcode, non-NIST)
- `script/slh_dsa_sha2_128_24_signer.py`, `script/slh_dsa_keccak_128_24_signer.py` — pure-Python reference signers (slow — keygen builds a 2^22-leaf XMSS)
- `signers/sphincsplus-128-24/` — fork of sphincs/sphincsplus ref with a `params-*-128-24.h` header and w=4 support; ~2-4 min for a full NIST-params sign, callable from Forge tests via `script/slh_dsa_sha2_128_24_fast_signer.py`
- `signers/sphincsplus-128-24/crosscheck.py` — validates that the C and Python signers produce identical bytes at matching params
- `test/SLH-DSA-SHA2-128-24-Test.t.sol` — Forge FFI test that signs with the C binary and verifies on-chain

Legacy signers / UserOp / frame-tx (`legacy/script/`): `signer.py`,
`jardin_signer.py`, `jardin_t0_signer.py`, `jardin_userop.py`,
`jardin_t0_userop.py`, `jardin_frame_tx.py`, etc. — see `legacy/README.md`.

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
