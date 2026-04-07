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

## Verified Kernel

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
| **C6** | **FORS+C h=24 d=2 a=16 k=8** | **3352 bytes** | **156K** | **301K** | **128-bit @ 2^20 sigs** |

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

## Deployed Contracts & Transactions

### Sepolia (ERC-4337 Hybrid)

| Contract | Address |
|---|---|
| Factory | [`0x6c523b...`](https://sepolia.etherscan.io/address/0x6c523b4FC4DBDB57067a516ad1186329d6ba0D5e) |
| C6 Account (ASM) | [`0x1e8320...`](https://sepolia.etherscan.io/address/0x1e8320b5ce068d72aab8a4777d0a462bcd87ce11) |
| C6 Verifier (ASM) | [`0xD8acb5...`](https://sepolia.etherscan.io/address/0xD8acb5342d8b46dCB388A82C582a5A24BF68e40A) |
| C6 Verifier (`verity_contract`) | [`0xd006d9...`](https://sepolia.etherscan.io/address/0xd006d936e39d9b997775b5fACe204e4aF58c86A5) |
| C6 Account (`verity_contract`) | [`0x5961f6...`](https://sepolia.etherscan.io/address/0x5961f6DeFBa70658736489Fdfc49Dac9E035A77A) |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |

**Transactions:**

| Description | Gas | Tx |
|---|---|---|
| Real ETH transfer (ASM verifier) | 300,826 | [`0xe63296bf...`](https://sepolia.etherscan.io/tx/0xe63296bfe277433dcb28a9bbb03eec25d2ef860041338e270225eb1d6fa7ca68) |
| Real ETH transfer (`verity_contract` verifier) | 383,396 | [`0xd63462d0...`](https://sepolia.etherscan.io/tx/0xd63462d0e78342181a0bf884c1ae0dc60e8b6cf0df278f21724903bba83bc38d) |

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

| Contract | Address |
|---|---|
| C6 Verifier | [`0x5081a3...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x5081a39b8A5f0E35a8D959395a630b68B74Dd30f) |
| Frame Account | [`0x1fA02b...`](https://demo.eip-8141.ethrex.xyz:8082/address/0x1fA02b2d6A771842690194Cf62D91bdd92BfE28d) |

**Transactions:**

| Description | Gas | Tx |
|---|---|---|
| Frame tx — SPHINCS+ C6 pure PQ (block 586490) | 229,776 | [`0x36200cda...`](https://demo.eip-8141.ethrex.xyz:8082/tx/0x36200cdab09b0147811e22493cf2ba50e9467d365b2f2a77562629f11c18acb0) |

Chain ID: 1729. Both VERIFY (159K gas) and SENDER frames succeeded — no ECDSA, pure post-quantum. The frame tx gas (230K) is lower than the 4337 hybrid (301K) because there is no EntryPoint overhead or ECDSA verification.

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
  --factory 0x6c523b4FC4DBDB57067a516ad1186329d6ba0D5e \
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
forge test --match-contract MerkleKernelVerityTest -vv  # Verity kernel artifact replay
cd signer-wasm && cargo test --release -- --ignored  # Rust signer roundtrip
```

## Formal Verification (Lean 4 / Verity)

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
