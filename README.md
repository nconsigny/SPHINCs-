# SPHINCs- — Post-Quantum Ethereum Accounts

---

> ## WARNING: RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE
>
> This codebase is a scheme exploration for lightweight variants of SPHINCS+.
> It has **not been audited**, contains **no security guarantees**, and is
> **not safe to use with real funds**. Cryptographic parameters, key derivation,
> and contract logic have not been reviewed by any third party.
> **Use on testnets only.**

---

Post-quantum signature verification on Ethereum using hash-based signatures (SPHINCS+ variants). Supports ERC-4337 hybrid accounts (ECDSA + SPHINCS+) and native EIP-8141 frame transaction accounts (pure PQ).

## Architecture

### ERC-4337 Hybrid Account
```
BIP-39 mnemonic (12/24 words)
    │
    ▼  PBKDF2 → 512-bit seed
    │
    ├── HMAC-SHA512("sphincs-c6-v1") → SPHINCS+ keypair (quantum-safe path)
    │       ├── pkSeed + pkRoot → stored in verifier contract (on-chain)
    │       └── sk_seed         → never stored, rederived per session
    │
    └── BIP-32 m/44'/60'/0'/0/0 → ECDSA key (independent, signs UserOps)

UserOp signature = abi.encode(ecdsaSig[65], sphincsSig[3352])

EntryPoint.handleOps()
    └── SphincsAccount._validateSignature()
            ├── ECDSA.recover(userOpHash, ecdsaSig) == owner
            └── verifier.staticcall(verify(userOpHash, sphincsSig)) == true
```

### EIP-8141 Frame Transaction Account (Pure PQ)
```
Frame Transaction (type 0x06)
    ├── Frame 0 (VERIFY): SPHINCS+ C6 verification → APPROVE
    └── Frame 1 (SENDER): ETH transfer / contract call
```
No ECDSA required — the account validates with SPHINCS+ only via the APPROVE opcode.

## Variants

| Variant | Scheme | Sig size | Verify gas | 4337 total | Security |
|---|---|---|---|---|---|
| C2 | FORS+C h=18 d=2 | 4040 bytes | 193K | 412K | 128-bit |
| C3 | PORS+FP h=27 d=3 | 4188 bytes | 261K | 444K | 128-bit |
| C5 | PORS+FP h=20 d=2 w=32 | 2888 bytes | 233K | 404K | 128-bit |
| **C6** | **FORS+C h=24 d=2 a=16 k=8** | **3352 bytes** | **156K** | **335K** | **128-bit @ 2^20 sigs** |

C6 is the gas-optimal candidate, found via calibrated EVM cost model (see `SPHINCS-Parameters/`).

## Key Derivation

### BIP-39 Path (Rust WASM signer)

The Rust signer (`signer-wasm/`) derives SPHINCS+ keys from a standard BIP-39 mnemonic. The SPHINCS+ secret key is derived directly from the BIP-39 seed via HMAC-SHA512, **bypassing ECDSA entirely** — a quantum attacker who recovers the ECDSA private key via Shor's algorithm learns nothing about `sk_seed`.

```
BIP-39 mnemonic (12 or 24 words)
    │
    ▼  PBKDF2 → 512-bit seed
    │
    ├──▶ HMAC-SHA512(key="sphincs-c6-v1", data=seed) → sphincs_master (64 bytes)
    │       │
    │       ├──▶ keccak256("pk_seed" || sphincs_master[0..32]) & N_MASK → pkSeed  (public, on-chain)
    │       └──▶ keccak256("sk_seed" || sphincs_master[0..32])          → sk_seed (secret, never stored)
    │                                                                         │
    │                                                                         ▼
    │                                                                   hypertree build → pkRoot (public, on-chain)
    │
    └──▶ BIP-32 m/44'/60'/0'/0/0 → ECDSA address (independent, for account identification only)
```

Users can use their existing 12/24 word seed phrase. The SPHINCS+ keypair and ECDSA address are both deterministically derived from the same mnemonic, but through independent paths — compromising one does not compromise the other.

### Legacy Path (Python signer)

The Python signer derives directly from an ECDSA private key + variant tag, without BIP-39. This path is **not post-quantum safe** if the ECDSA public key has been exposed on-chain.

## Signers

| Signer | Language | Platform | C6 Sign Time | BIP-39 |
|---|---|---|---|---|
| `script/signer.py` | Python | CLI | ~30s | No (private key only) |
| `signer-wasm/` | Rust | Native + WASM | ~3s native, ~6-15s browser | **Yes** |

The Rust signer produces byte-identical output to the Python signer (8/8 cross-validation tests passing).

```bash
# Build WASM signer
cd signer-wasm && wasm-pack build --release --target web

# Run tests (including full signing roundtrip)
cargo test --release -- --ignored
```

## Formal Verification (Lean 4 / Verity)

The `verity/` directory contains a Lean 4 formal model and a Verity CompilationModel of the C6 verifier. The [Verity](https://github.com/Th0rgal/verity) compiler generates the **entire verification pipeline** — H_msg, FORS+C, hypertree, WOTS chains — directly from the Lean model. No opaque oracle; every keccak hash chain is traceable to the EDSL source.

```
verity/
├── SphincsC6/           ← Lean 4 functional model (zero sorry, 14 theorems)
│   ├── Types.lean       ← C6 parameters, sig types
│   ├── Hash.lean        ← Keccak primitives + collision resistance axioms
│   ├── WotsC.lean       ← WOTS+C w=16 verification
│   ├── ForsC.lean       ← FORS+C forced-zero last tree
│   ├── Hypertree.lean   ← D=2 layers, subtree_h=12
│   ├── Contract.lean    ← Verity Contract monad + security properties
│   └── Spec.lean        ← Proven: param consistency, sig size, soundness
├── SphincsC6Full.lean   ← Full CompilationModel EDSL (no oracle)
└── artifacts/
    └── SphincsC6Full.yul ← Verity-compiled (273 lines, 1225 bytes runtime)
```

```bash
# Compile from Lean to Yul (no --link, no oracle)
lake exe verity-compiler --module Contracts.SphincsC6Full -o artifacts/yul
```

The Verity-compiled contract verifies the same signatures as the hand-optimized ASM, with 9% gas overhead (255K vs 234K EOA call) from additional ABI safety checks.

## Deployed Contracts & Transactions

### Sepolia (ERC-4337 Hybrid)

| Contract | Address |
|---|---|
| Factory (C2-C6) | [`0x795C1386...`](https://sepolia.etherscan.io/address/0x795C138673E934c3809477d2507fBF86985f8c2F) |
| C6 Account | [`0x79169...`](https://sepolia.etherscan.io/address/0x7916968db92A3fbaFBb13b61B60C940811689337) |
| C6 Verifier (ASM) | [`0xc8aa8...`](https://sepolia.etherscan.io/address/0xc8aa83f6419f95bd8728ee9df225e93c6694da6b) |
| C6 Verifier (Verity, full) | [`0xddd28...`](https://sepolia.etherscan.io/address/0xddd28faE24f10B029F55dc674d1c6105AFfBe1C8) |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

**Transactions:**

| Description | Gas | Tx |
|---|---|---|
| C6 hybrid UserOp (ECDSA + SPHINCS+) | 335,021 | [`0x8ffc857b...`](https://sepolia.etherscan.io/tx/0x8ffc857b5858175e9bcf7f1121653eef320e6b13f7a89b20f59d09f7bec189d1) |
| C6 EOA verify — hand-optimized ASM | 231,350 | [`0xf91c864f...`](https://sepolia.etherscan.io/tx/0xf91c864f1e51fbc65d1a25815304632b2c10feba8b12c1ca2e6562dbfb2423a3) |
| C6 EOA verify — Verity-compiled (full) | 254,971 | [`0xddd28f...`](https://sepolia.etherscan.io/address/0xddd28faE24f10B029F55dc674d1c6105AFfBe1C8) |
| C2 hybrid UserOp | 412,126 | See `trace_c2_summary.txt` |
| C5 hybrid UserOp | 403,636 | See `trace_c5_summary.txt` |

**Gas breakdown note:** The EOA verify calls (231K / 255K) include the 21K base transaction cost and ~54K calldata cost for the 3352-byte signature. The pure SPHINCS+ compute cost is **~156K gas** — visible in the C6 hybrid UserOp trace as the inner `verifier.staticcall()`, where calldata is already paid by the outer transaction.

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

| Contract | Address |
|---|---|
| C6 Verifier | [`0x7969c5...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x7969c5eD335650692Bc04293B07F5BF2e7A673C0) |
| Frame Account | [`0xFD4718...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xFD471836031dc5108809D173A067e8486B9047A3) |

**Transactions:**

| Description | Gas | Tx |
|---|---|---|
| Frame tx — SPHINCS+ C6 pure PQ (block 534292) | 229,867 | [`0xb2dc8be4...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0xb2dc8be4ad34285c6eb835db675ef0463d23d5fd53c56f543ee0fe29aa7ecfc3) |

Chain ID: 1729. Both VERIFY and SENDER frames succeeded — no ECDSA, pure post-quantum. The frame tx gas (230K) is lower than the 4337 hybrid (335K) because there is no EntryPoint overhead or ECDSA verification.

## Setup

```bash
# Solidity
forge build

# Python signer
pip install eth-account eth-abi requests pycryptodome

# Rust WASM signer
cd signer-wasm && cargo build --release
```

## Usage

```bash
# Create hybrid account (ERC-4337)
python3 script/send_userop.py create \
  --factory 0x795C138673E934c3809477d2507fBF86985f8c2F \
  --ecdsa-key $PRIVATE_KEY --variant c6

# Send hybrid UserOp
python3 script/send_userop.py send \
  --account <account> --ecdsa-key $PRIVATE_KEY \
  --to <recipient> --value 0.001 --variant c6

# Send EIP-8141 frame tx (pure PQ, ethrex testnet)
python3 script/frame_tx.py send \
  --account <frame_account> --to <recipient> --value 0.001
```

## Tests

```bash
forge test                                    # all tests
forge test --match-contract C6Differential    # C6 cross-validation
cd signer-wasm && cargo test --release -- --ignored  # Rust signer roundtrip
```

## References

- [ePrint 2025/2203](https://eprint.iacr.org/2025/2203) — Blockstream SPHINCS+ parameter optimization (WOTS+C, FORS+C)
- [SPHINCS-Parameters](https://github.com/nconsigny/SPHINCS-Parameters) — EVM-adapted parameter search with calibrated gas model
- [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) — Frame transactions (native account abstraction)
- [Verity](https://github.com/Th0rgal/verity) — Lean 4 → EVM formally verified smart contracts
