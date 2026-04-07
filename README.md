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

### Shared Verifier Model

The SPHINCS- C6 verifier is **deployed once** and shared by all accounts. Each account stores its own public keys (`pkSeed`, `pkRoot`) and calls the shared verifier with its keys as arguments. Follows the [ZKnox/Kohaku](https://github.com/ethereum/kohaku/tree/master/examples/pq-account) pattern.

```
SphincsC6Asm (deployed once, stateless)
    ↑ verify(pkSeed, pkRoot, message, sig) → bool
    │
    ├── SphincsAccount (4337, per-user)     ← stores keys + ECDSA owner
    └── FrameAccount (EIP-8141, per-user)   ← stores keys, validates before forwarding
```

### ERC-4337 Hybrid Account
```
BIP-39 mnemonic (12/24 words)
    │
    ├── SPHINCS+ keypair (quantum-safe, via HMAC-SHA512)
    │       ├── pkSeed + pkRoot → stored in account contract
    │       └── sk_seed → never stored
    │
    └── ECDSA key (via BIP-32 m/44'/60'/0'/0/0)

UserOp signature = abi.encode(ecdsaSig[65], sphincsSig[3352])

EntryPoint.handleOps()
    └── SphincsAccount._validateSignature()
            ├── ECDSA.recover(userOpHash, ecdsaSig) == owner
            └── sharedVerifier.verify(pkSeed, pkRoot, userOpHash, sphincsSig) == true
```

### EIP-8141 Frame Transaction (Pure PQ)
```
Frame Transaction (type 0x06)
    ├── Frame 0 (VERIFY): frame account validates keys match storage,
    │     forwards to shared verifier → APPROVE
    └── Frame 1 (SENDER): ETH transfer / contract call
```
No ECDSA — pure post-quantum. The frame account checks that `pkSeed`/`pkRoot` in the calldata match its own storage before forwarding, preventing key substitution attacks.

## C6 Parameters

| | Value |
|---|---|
| Scheme | FORS+C (W+C_F+C) |
| h=24, d=2 | subtree_h=12, 2 hypertree layers |
| a=16, k=8 | 7 FORS trees + 1 forced-zero |
| w=16, l=32 | WOTS+C with target_sum=240 |
| Sig size | 3352 bytes |
| Verify gas | ~156K (pure compute) |
| Security | 128-bit @ 2^20 signatures |

Domain-separated H_msg (160-byte hash) prevents collision with ThPair/wotsDigest.

## Key Derivation

### BIP-39 Path (Rust WASM signer)

```
BIP-39 mnemonic (12 or 24 words)
    │
    ├──▶ HMAC-SHA512("sphincs-c6-v1", seed) → pkSeed, sk_seed (quantum-safe)
    └──▶ BIP-32 m/44'/60'/0'/0/0 → ECDSA address (independent)
```

SPHINCS+ and ECDSA are derived through independent paths — compromising one does not compromise the other.

## Signers

| Signer | Language | C6 Sign Time | BIP-39 |
|---|---|---|---|
| `script/signer.py` | Python | ~30s | No |
| `signer-wasm/` | Rust/WASM | ~3s native | **Yes** |

```bash
cd signer-wasm && wasm-pack build --release --target web
cargo test --release -- --ignored  # 9/9 tests
```

## Deployed Contracts & Transactions

### Sepolia (ERC-4337 Hybrid)

| Contract | Address |
|---|---|
| Shared C6 Verifier | [`0xb8Cd1B...`](https://sepolia.etherscan.io/address/0xb8Cd1B03c999FeE1735100B47bBF0D047610eBAA) |
| Factory | [`0xc2546e...`](https://sepolia.etherscan.io/address/0xc2546e0a8A7b854B911e8DFBA287a1C746267B2b) |
| Account | [`0xE350BA...`](https://sepolia.etherscan.io/address/0xE350BA9A66045b19B668eA197077D4834e03C65D) |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

| Description | Gas | Tx |
|---|---|---|
| Real ETH transfer (hybrid, shared verifier) | 315,137 | [`0x65e11e83...`](https://sepolia.etherscan.io/tx/0x65e11e83e451326d0f2fda2af9b00b9c6ed4c5481d508194f9e22bcbcc1888ad) |

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

| Contract | Address |
|---|---|
| Shared C6 Verifier | [`0x2E2Ed0...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x2E2Ed0Cfd3AD2f1d34481277b3204d807Ca2F8c2) |
| Frame Account | [`0x8198f5...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7) |

| Description | Gas | Tx |
|---|---|---|
| Frame tx — pure PQ (block 726003) | 231,692 | [`0x8a903f9d...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x8a903f9d586c58176b2673d2f0a9243ace3b5af4e35259bd474f0a9705112b90) |

Chain ID: 1729. VERIFY frame (161K) validates keys + SPHINCS+ signature, SENDER frame executes. No ECDSA, pure post-quantum.

## Setup

```bash
forge build
pip install eth-account eth-abi requests pycryptodome
cd signer-wasm && cargo build --release
```

## Usage

```bash
# Deploy shared verifier + factory (once)
forge script script/DeploySepolia.s.sol --rpc-url sepolia --broadcast

# Create account
python3 script/send_userop.py create \
  --factory <factory> --ecdsa-key $PRIVATE_KEY --variant c6

# Send hybrid UserOp
python3 script/send_userop.py send \
  --account <account> --ecdsa-key $PRIVATE_KEY \
  --to <recipient> --value 0.001 --variant c6

# Send EIP-8141 frame tx (pure PQ, ethrex)
python3 script/frame_tx.py send \
  --account <frame_account> --to <recipient> --value 0.001
```

## Tests

```bash
forge test
cd signer-wasm && cargo test --release -- --ignored
```

## Formal Verification (Lean 4 / Verity)

### Verified Kernel

This repo now includes a very small formally checked artifact:

- a Merkle acceptance kernel for SPHINCS-style witnesses,
- with the public claim that `verifyPath` accepts exactly the typed witnesses whose reconstructed root matches the stored root,
- and `verifyPackedPath` accepts exactly the canonical packed encodings whose decoded typed witness is accepted by that same rule,
- with read-only verification,
- and with malformed packed encodings rejected explicitly when direction bits outside the low 4 bits are set.

The verified core is intentionally smaller than a full SPHINCS verifier. Parsing, witness derivation, and full cryptographic verification stay outside that proof boundary unless they can be specified just as cleanly.

Why that is still useful:

- a real verifier can derive or decode a typed witness off-chain or in unverified code,
- pass that witness to the kernel,
- and rely on a machine-checked guarantee about the exact on-chain acceptance rule.

### Full C6 Verifier

The verified artifact in this repo is a small acceptance kernel in [`verity/SphincsKernel/`](verity/SphincsKernel/).

It proves a narrow but strong property:

- the Lean model defines exactly which fixed-depth Merkle witnesses are accepted,
- a typed witness reconstructs exactly one root,
- `verifyPath` returns `true` iff that reconstructed root equals the configured root,
- `verifyPackedPath` returns `true` iff the packed input is canonical, decodes to a typed witness, and that typed witness is accepted by the same root-equality rule,
- verification is read-only.

The kernel exposes two interfaces:

- `verifyPath`: explicit witness fields plus 4 direction booleans,
- `verifyPackedPath`: the same witness with directions packed into the low 4 bits of one word.

This is useful because it makes one concrete class of bugs impossible: the deployed acceptance contract cannot silently accept a different witness than the Lean model accepts.

What is not claimed:

- this is not a proof of full SPHINCS cryptographic security,
- this is not an end-to-end proof of the entire production C6 verifier,
- the kernel's `compress` function is a small stand-in, not a real SPHINCS hash primitive,
- parsing, witness derivation, and protocol integration are outside the verified kernel.

The repo also includes a direct EVM replay test for the kernel:

- it recompiles `verity/artifacts/sphincs-kernel/MerkleKernel.yul`,
- deploys that bytecode in Foundry,
- checks named vectors,
- fuzzes both explicit and packed witness entrypoints against a Solidity reference model.

See [`verity/README.md`](verity/README.md) for the exact specs, theorem shape, strict build commands, and trust boundary.

## References

- [ePrint 2025/2203](https://eprint.iacr.org/2025/2203) — Blockstream SPHINCS+ parameter optimization (WOTS+C, FORS+C)
- [SPHINCS-Parameters](https://github.com/nconsigny/SPHINCS-Parameters) — EVM-adapted parameter search with calibrated gas model
- [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) — Frame transactions (native account abstraction)
- [Verity](https://github.com/Th0rgal/verity) — Lean 4 → EVM formally verified smart contracts
- [ZKnox/Kohaku](https://github.com/ethereum/kohaku) — PQ account pattern (shared verifier model)
