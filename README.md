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
    ▼  BIP-44: m/44'/60'/0'/0/0
ECDSA private key
    │
    ├── signs UserOp (classical, secp256k1)
    │
    └── derives SPHINCS+ keypair (keccak256 chain)
            │
            ├── pkSeed + pkRoot → stored in verifier contract (on-chain)
            └── sk_seed         → never stored, rederived per session

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

### BIP-39/44 Path (Rust WASM signer)

The Rust signer (`signer-wasm/`) derives SPHINCS+ keys from a standard BIP-39 mnemonic:

```
BIP-39 mnemonic (12 or 24 words)
    │
    ▼  PBKDF2 → 512-bit seed
    │
    ▼  BIP-32 derivation at m/44'/60'/0'/0/0
    │
ECDSA private key (32 bytes)
    │
    ▼  keccak256("sphincs_signer_v1" || keccak256(key))
entropy
    ├──▶ keccak256("pk_seed" || entropy) & N_MASK → pkSeed  (public, on-chain)
    └──▶ keccak256("sk_seed" || entropy)          → sk_seed (secret, never stored)
                                                        │
                                                        ▼
                                                  hypertree build → pkRoot (public, on-chain)
```

Users can use their existing 12/24 word seed phrase. The SPHINCS+ keypair is deterministically derived from the same mnemonic as their Ethereum account.

### Legacy Path (Python signer)

The Python signer derives directly from an ECDSA private key + variant tag, without BIP-39.

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

The `verity/` directory contains a Lean 4 formal model of the C6 verifier, compilable via the [Verity](https://github.com/Th0rgal/verity) framework.

```
verity/
├── SphincsC6/           ← Lean 4 functional model (zero sorry, 14 theorems)
│   ├── Types.lean       ← C6 parameters, sig types
│   ├── Hash.lean        ← Keccak primitives + collision resistance axioms
│   ├── WotsC.lean       ← WOTS+C w=16 verification
│   ├── ForsC.lean       ← FORS+C forced-zero last tree
│   ├── Hypertree.lean   ← D=2 layers, subtree_h=12
│   ├── Contract.lean    ← Verity Contract monad + oracle model
│   └── Spec.lean        ← Proven: param consistency, sig size, soundness
├── external-libs/       ← SphincsC6Verify.yul (full verification oracle)
└── artifacts/           ← Verity-compiled SphincsC6Verifier.yul
```

The Verity compiler generates a complete Yul contract from the Lean model:
```bash
lake exe verity-compiler --module Contracts.SphincsC6.SphincsC6 \
  --link examples/external-libs/SphincsC6Verify.yul -o artifacts/yul
```

Both the hand-optimized and Verity-compiled versions are deployed on Sepolia and verify the same signatures.

## Deployed Contracts & Transactions

### Sepolia (ERC-4337 Hybrid)

| Contract | Address |
|---|---|
| Factory (C2-C6) | [`0x795C1386...`](https://sepolia.etherscan.io/address/0x795C138673E934c3809477d2507fBF86985f8c2F) |
| C6 Account | [`0x79169...`](https://sepolia.etherscan.io/address/0x7916968db92A3fbaFBb13b61B60C940811689337) |
| C6 Verifier (ASM) | [`0xc8aa8...`](https://sepolia.etherscan.io/address/0xc8aa83f6419f95bd8728ee9df225e93c6694da6b) |
| C6 Verifier (Verity) | [`0x77bE5...`](https://sepolia.etherscan.io/address/0x77bE5c7E9196599478eC79fB815AcB21eb00Fd12) |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

**Transactions:**

| Description | Gas | Tx |
|---|---|---|
| C6 hybrid UserOp (ECDSA + SPHINCS+) | 335,021 | [`0x8ffc857b...`](https://sepolia.etherscan.io/tx/0x8ffc857b5858175e9bcf7f1121653eef320e6b13f7a89b20f59d09f7bec189d1) |
| C6 verify — hand-optimized ASM | 231,350 | [`0xf91c864f...`](https://sepolia.etherscan.io/tx/0xf91c864f1e51fbc65d1a25815304632b2c10feba8b12c1ca2e6562dbfb2423a3) |
| C6 verify — Verity-compiled | 268,107 | [`0xca402720...`](https://sepolia.etherscan.io/tx/0xca4027205df0960cbb0982e05898ac2d7f877f8c0afaa41637934c3342d290ea) |
| C2 hybrid UserOp | 412,126 | See `trace_c2_summary.txt` |
| C5 hybrid UserOp | 403,636 | See `trace_c5_summary.txt` |

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

| Contract | Address |
|---|---|
| C6 Verifier | [`0x7969c5...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x7969c5eD335650692Bc04293B07F5BF2e7A673C0) |
| Frame Account | [`0xFD4718...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xFD471836031dc5108809D173A067e8486B9047A3) |

**Transactions:**

| Description | Tx |
|---|---|
| Frame tx — SPHINCS+ C6 pure PQ verification (block 534292) | [`0xb2dc8be4...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0xb2dc8be4ad34285c6eb835db675ef0463d23d5fd53c56f543ee0fe29aa7ecfc3) |

Chain ID: 1729. Both VERIFY and SENDER frames succeeded — no ECDSA, pure post-quantum.

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
