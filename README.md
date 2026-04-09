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

All variants use WOTS+C / FORS+C (ePrint 2025/2203), n=128-bit, d=2, domain-separated H_msg (160-byte hash).

| Variant | h | a | k | w | l | swn | Sig | sign_h | Verify | Frame | 4337 | sec_14 | sec_16 | sec_18 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| C6 | 24 | 16 | 8 | 16 | 32 | 240 | 3352 B | 5.7M | 156K | 232K | 333K | 128 | 128 | 128 | 128 |
| **C7** | **24** | **16** | **8** | **8** | **43** | **151** | **3704 B** | **4.3M** | **127K** | **210K** | **318K** | **128** | **128** | **128** | **128** |
| C8 | 20 | 13 | 12 | 16 | 32 | 162 | 3848 B | 1.4M | 194K | 271K | 377K | 128 | 128 | 128 | 128 |
| **C9** | **20** | **12** | **11** | **8** | **43** | **208** | **3816 B** | **1.3M** | **117K** | **195K** | **300K** | **128** | **128** | **121.6** | **112.6** |
| C10 | 18 | 11 | 13 | 8 | 43 | 205 | 4008 B | 609K | 115K | 203K | 308K | 128 | 128 | 118.3 | 104.5 |
| C11 | 16 | 11 | 13 | 8 | 43 | 203 | 3976 B | 292K | 116K | 202K | 308K | 128 | 118.3 | 104.5 | 86.1 |

- **sign_h**: keccak256 calls during signing (determines signer speed)
- **sec_N**: security bits at 2^N signatures per key
- **Verify**: pure verifier gas (Foundry `gasleft()` measurement)
- **Frame**: total EIP-8141 frame tx gas (ethrex)
- **4337**: total `handleOps` tx gas (Sepolia)

C7 is the best gas-efficient variant with full 128-bit security at 2^20 signatures. C9 offers 22% lower frame gas but requires key rotation before 2^16 signatures to maintain 128-bit security.

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

EntryPoint v0.9: `0x433709009B8330FDa32311DF1C2AFA402eD8D009` (Sepolia)

### Sepolia (ERC-4337 Hybrid)

| Variant | Verifier | Account | Gas | Tx |
|---|---|---|---|---|
| C7 | [`0x694C0a...`](https://sepolia.etherscan.io/address/0x694C0a72290FEd14c3641E0975F8d0939F84ee23) | [`0x8b8d01...`](https://sepolia.etherscan.io/address/0x8b8d01b7c553a3a0267eb646ad8b68513457c144) | 318K | [`0xced796ed...`](https://sepolia.etherscan.io/tx/0xced796ed90b82006ecedf896b4b629118c95545b307542fd26a891a367bd3f95) |
| C8 | [`0x9DF5b4...`](https://sepolia.etherscan.io/address/0x9DF5b45624752E0D87b2DBCA6B07E8cC977be8B2) | [`0xdD58f3...`](https://sepolia.etherscan.io/address/0xdD58f35c520914fd9aefCd492d8577700Ef0A9a1) | 377K | [`0x748e2aed...`](https://sepolia.etherscan.io/tx/0x748e2aed29608a15f1b2a5d43cb0f5d66553fc32980ece366edd282f36361eac) |
| C9 | [`0x18F005...`](https://sepolia.etherscan.io/address/0x18F005EECd41624644AA364bA8857258FEB3C26D) | [`0xA94111...`](https://sepolia.etherscan.io/address/0xA941116763AE386a50133c5af40356c9D93b2978) | 300K | [`0x8366513b...`](https://sepolia.etherscan.io/tx/0x8366513b096ee53dd1cb105363ab21a52267dd966b822b4bb2cf5492abf1550f) |
| C10 | [`0x1500ad...`](https://sepolia.etherscan.io/address/0x1500ad392631CFe002c55094e38A280Bb0C6129f) | [`0xa46790...`](https://sepolia.etherscan.io/address/0xa4679058B95cac5112D3b25AA7086d4fe1712f62) | 308K | [`0x724c1b99...`](https://sepolia.etherscan.io/tx/0x724c1b99a747aeb636e93eb11636003dc453da15b2b6f24bec3f5267393633d7) |
| C11 | [`0xC25ef5...`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) | [`0x3C3b0c...`](https://sepolia.etherscan.io/address/0x3C3b0c3498E5ed9350F6fBFA0Ef8dC55f524eA50) | 308K | [`0x9fba169c...`](https://sepolia.etherscan.io/tx/0x9fba169ca76b6712586e44e1a4a2d0407b8b8b9ce767272a193e41a756260b74) |

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

Chain ID: 1729. VERIFY frame reads keys from storage, STATICCALLs shared verifier, APPROVEs. No ECDSA.

| Variant | Verifier | Frame Account | Gas | Verify | Tx |
|---|---|---|---|---|---|
| C7 | [`0xf953b3...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xf953b3A269d80e3eB0F2947630Da976B896A8C5b) | [`0xAA292E...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xAA292E8611aDF267e563f334Ee42320aC96D0463) | 210K | 135K | [`0xaf875b26...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0xaf875b2615b5c3610ea619b922588ee66338824b1e0e130112033f5a7904cf3e) |
| C8 | [`0xCace1b...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xCace1b78160AE76398F486c8a18044da0d66d86D) | [`0xD5ac45...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xD5ac451B0c50B9476107823Af206eD814a2e2580) | 271K | 194K | [`0x512e728d...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x512e728db2408b2c470202c5ac7deeda3d3331b9b2683ec1136fdca4cd46d980) |
| C9 | [`0xc0F115...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xc0F115A19107322cFBf1cDBC7ea011C19EbDB4F8) | [`0xc96304...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xc96304e3c037f81dA488ed9dEa1D8F2a48278a75) | 195K | 117K | [`0x393588ec...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x393588eceeda4839371f103e16b10c5e2900416d7b194faee8478b6561792813) |
| C10 | [`0xD0141E...`](https://demo.eip-8141.ethrex.xyz:8082/address/0xD0141E899a65C95a556fE2B27e5982A6DE7fDD7A) | [`0x07882A...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x07882Ae1ecB7429a84f1D53048d35c4bB2056877) | 203K | 122K | [`0x0a2571f8...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x0a2571f8423ab4ec75e09623773b22ff91794a82d1b3db2d616b8af354730353) |
| C11 | [`0x315575...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x3155755b79aA083bd953911C92705B7aA82a18F9) | [`0x5bf5b1...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x5bf5b11053e734690269C6B9D438F8C9d48F528A) | 202K | 122K | [`0x053428f5...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x053428f530521a5c42c4d2406d1cfb8e07baefa0328c0e425045a3ba9317106b) |

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
