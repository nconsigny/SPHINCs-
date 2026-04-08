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

The SPHINCS- verifier is **deployed once** and shared by all accounts. Follows the [ZKnox/Kohaku](https://github.com/ethereum/kohaku/tree/master/examples/pq-account) pattern.

```
SPHINCs-Asm (deployed once, stateless, pure)
    ↑ verify(pkSeed, pkRoot, message, sig) → bool
    │
    ├── SphincsAccount (4337)       ← keys in storage, rotatable
    └── FrameAccount (EIP-8141)     ← keys in storage, rotatable
```

### ERC-4337 Hybrid Account

The account stores keys as immutables and passes them to the shared verifier on each UserOp.

```
EntryPoint.handleOps()
    └── SphincsAccount._validateSignature()
            ├── ECDSA.recover(userOpHash, ecdsaSig) == owner
            └── sharedVerifier.verify(pkSeed, pkRoot, userOpHash, sphincsSig) == true
```

### EIP-8141 Frame Transaction (Pure PQ)

The frame account has keys baked into its bytecode — no storage, no calldata overhead for keys. It receives `sigHash + raw_sig`, builds the full ABI call to the shared verifier internally, and calls APPROVE on success.

```
Frame Transaction (type 0x06)
    ├── Frame 0 (VERIFY): frame account builds verify(pkSeed, pkRoot, sigHash, sig)
    │     from embedded keys + calldata → STATICCALLs shared verifier → APPROVE
    └── Frame 1 (SENDER): ETH transfer / contract call
```
No ECDSA — pure post-quantum. Keys are stored in EVM storage (not bytecode) to support future key rotation via `rotateKeys()` — costs ~4K gas per verify but keeps the same account address across key changes.

## Variants

| Variant | w | l | Sig size | Verify gas | 4337 total | Frame tx | Security |
|---|---|---|---|---|---|---|---|
| C6 | 16 | 32 | 3352 bytes | 156K | 333K | 232K | 128-bit @ 2^20 |
| **C7** | **8** | **43** | **3704 bytes** | **127K** | **318K** | **210K** | **128-bit @ 2^20** |

Both share: h=24, d=2, a=16, k=8 (FORS+C). C7 trades +352 bytes sig for 19% less compute (fewer chain hash steps). Domain-separated H_msg (160-byte hash).

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
| Shared C7 Verifier | [`0x694C0a...`](https://sepolia.etherscan.io/address/0x694C0a72290FEd14c3641E0975F8d0939F84ee23) |
| C7 Account | [`0x8b8d01...`](https://sepolia.etherscan.io/address/0x8b8d01b7c553a3a0267eb646ad8b68513457c144) |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

| Description | Gas | Verify | Tx |
|---|---|---|---|
| C7 real ETH transfer (4337 hybrid) | 318K | 127K | [`0xced796ed...`](https://sepolia.etherscan.io/tx/0xced796ed90b82006ecedf896b4b629118c95545b307542fd26a891a367bd3f95) |

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

| Contract | Address |
|---|---|
| Shared C7 Verifier | [`0xf953b3...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xf953b3A269d80e3eB0F2947630Da976B896A8C5b) |
| C7 Frame Account (v2) | [`0xAA292E...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xAA292E8611aDF267e563f334Ee42320aC96D0463) |

| Description | Gas | Verify | Tx |
|---|---|---|---|
| C7 frame tx — pure PQ (block 802432) | 210K | 135K | [`0xaf875b26...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0xaf875b2615b5c3610ea619b922588ee66338824b1e0e130112033f5a7904cf3e) |

Chain ID: 1729. VERIFY frame reads keys from storage, runs SPHINCS+ C7 verification, SENDER frame executes. No ECDSA, pure post-quantum.

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
