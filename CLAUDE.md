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
| `JardinForsCVerifier.sol` | JARDÍN FORS+C-only verifier: k=26 a=5, verify=~66K |
| `JardinAccount.sol` | JARDÍN hybrid ECDSA + ERC-4337: Type 1 (C11) + Type 2 (FORS+C) |
| `JardinAccountFactory.sol` | Deploys JARDÍN accounts (ECDSA owner + two verifier refs) |
| `JardinFrameAccount.sol` | JARDÍN EIP-8141 frame account: pure PQ, rotatable keys |

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

Hybrid ECDSA + compact FORS+C account with stateless C10 fallback. Q_MAX=32 leaves per slot.

```
C10 Verifier (existing)          JardinForsCVerifier (NEW)
    ↑ verify(...)                     ↑ verifyForsCUnbalanced(...)
    │                                 │
    └── Type 1 (ECDSA+C10) ──────────┘── Type 2 (ECDSA+FORS+C)
                      │
                 JardinAccount (ERC-4337, hybrid)
                 ├── owner (ECDSA signer, rotatable)
                 ├── masterPkSeed, masterPkRoot (C10 identity)
                 ├── slots: mapping(H(r) → H(subPkSeed,subPkRoot))
                 └── Type 1: device registration + C10 fallback
                     Type 2: FORS+C compact (every subsequent tx)
```

| Event | Sig size | 4337 gas | Frequency |
|---|---|---|---|
| Device registration (Type 1) | 4,138 B | 323K | Once per 32 txs |
| Compact q=1 (Type 2) | 2,598 B | 174K | Every tx |
| Compact q=32 (Type 2) | 3,094 B | 189K | Last before rotation |
| Re-registration (Type 1) | 4,138 B | 289K | New slot |

FORS+C variant 2: k=26, a=5, n=16B (128-bit), Q_MAX=32. Keygen: ~79K hashes (~1s).
No on-chain leaf counter — q derived from signature length. FORS+C tolerates r=2 at 105-bit.
H_msg: 192-byte domain-separated hash (seed||root||R||msg||counter||domain).

### Off-chain Components

- `script/signer.py` — Python signer (c2/c6/c7 variants)
- `script/jardin_signer.py` — JARDÍN FORS+C signer (unbalanced tree + FORS+C)
- `script/send_userop.py` — ERC-4337 UserOp builder
- `script/frame_tx.py` — EIP-8141 frame tx builder
- `script/deploy_frame_account.py` — Deploys v2 frame account (keys in bytecode)
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
