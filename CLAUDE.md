# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SPHINCs- is a research prototype implementing post-quantum Ethereum accounts using SPHINCS+ hash-based signatures. Supports ERC-4337 hybrid accounts (ECDSA + SPHINCS+) and EIP-8141 frame transaction accounts (pure PQ). **Not audited, not production-safe.**

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

The SPHINCS+ verifier is deployed once and shared by all accounts. Each account stores its own keys and calls the shared verifier with keys as arguments.

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
| `SPHINCs-C6Asm.sol` | Shared C6 verifier: w=16, l=32, sig=3352 bytes, verify=156K gas |
| `SPHINCs-C7Asm.sol` | Shared C7 verifier: w=8, l=43, sig=3704 bytes, verify=127K gas |
| `SphincsAccount.sol` | ERC-4337 hybrid account (stores keys as immutables) |
| `SphincsAccountFactory.sol` | Deploys accounts (shared verifier in constructor) |
| `SphincsFrameAccount.sol` | Solidity reference for EIP-8141 frame account |

### Variants

| Variant | w | l | target_sum | Sig | Verify | 4337 | Frame |
|---|---|---|---|---|---|---|---|
| C6 | 16 | 32 | 240 | 3352 B | 156K | 333K | 232K |
| **C7** | **8** | **43** | **151** | **3704 B** | **127K** | **312K** | **206K** |

Both share: h=24, d=2, a=16, k=8, FORS+C, domain-separated H_msg (160 bytes).

### Off-chain Components

- `script/signer.py` — Python signer (c2/c6/c7 variants)
- `script/send_userop.py` — ERC-4337 UserOp builder
- `script/frame_tx.py` — EIP-8141 frame tx builder
- `script/deploy_frame_account.py` — Deploys v2 frame account (keys in bytecode)
- `signer-wasm/` — Rust WASM signer with BIP-39/44 key derivation

### Key Derivation

BIP-39 mnemonic → HMAC-SHA512 → SPHINCS+ keys (quantum-safe path, independent from ECDSA).

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
