# SPHINCs- — Post-Quantum Ethereum Accounts

---

> ## WARNING: RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE
>
> This codebase is a scheme exploration for lightweight variants of SPHINCS+ (called SPHINCs-).
> It has **not been audited**, contains **no security guarantees**, and is
> **not safe to use with real funds**. Cryptographic parameters, key derivation,
> and contract logic have not been reviewed by any third party.
> **Use on testnets only.**

---

Post-quantum signature verification on Ethereum using SPHINCs- — lightweight hash-based signatures derived from SPHINCS+. This repo focuses on the pure SPHINCs- research stack: the stateless C-series (C7 / C11 verifier + `SphincsAccount` / `SphincsAccountFactory` / `SphincsFrameAccount`), the plain-SPHINCS+ variant **C12** (`SPHINCs-C12Asm.sol`), and two new NIST SP 800-230 SLH-DSA-128-24 verifiers (a FIPS 205 bit-exact SHA-2 variant and a JARDIN-convention Keccak twin). Every current on-chain verifier shares one 32-byte ADRS layout and one set of tweakable-hash primitives, so a device port needs a single `sphincs_th*` implementation for every path.

Earlier verifier variants (C6 / C8 / C9 / C10) are frozen in [`legacy/`](./legacy/README.md) — same 32-byte ADRS kernel, different parameters.

The full JARDÍN hybrid-account design (ECDSA + SPHINCs-, ERC-4337 + EIP-8141, the plain-SPHINCS+ registration path, the plain-FORS compact path, all the Jardin* contracts and signers) lives in a separate repo: [`nconsigny/JARDIN`](https://github.com/nconsigny/JARDIN).

---

## Stateless SPHINCs- Architecture (C6–C11)

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

Active verifiers fall into three families:

- **C-series** (C7, C11) — WOTS+C / FORS+C (ePrint 2025/2203), n=128-bit, d=2, domain-separated H_msg (160-byte hash). Unlimited signatures per key, security degrades with N.
- **C12** — plain SPHINCS+ (SPX) with the JARDIN 32-byte ADRS kernel. n=128-bit, h=20, d=5, h'=4, plain WOTS+ checksum, keccak256 truncated to 128 bits. Unlimited signatures per key. (The JARDIN hybrid-account stack references this same contract as `JardinSpxVerifier` — see [`nconsigny/JARDIN`](https://github.com/nconsigny/JARDIN).)
- **SLH-DSA-128-24** — NIST SP 800-230 (April 2026 IPD), n=128-bit, single-tree (d=1, h=22), w=4, **2²⁴ signature limit per key**, 3,856-byte signature. SHA-2 variant is FIPS 205 bit-exact; Keccak variant is the JARDIN-convention twin (same dimensions, 32-byte JARDIN ADRS, LSB-first digest parsing).

| Variant | Family | h | a | k | w | l | swn | Sig | sign_h | Verify | Frame | 4337 | sec_14 | sec_16 | sec_18 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **C7** | WOTS+C / FORS+C | 24 | 16 | 8 | 8 | 43 | 151 | 3,704 B | 4.3 M | 127 K | 210 K | 318 K | 128 | 128 | 128 | 128 |
| **C11** | WOTS+C / FORS+C | 16 | 11 | 13 | 8 | 43 | 203 | 3,976 B | 292 K | 116 K | 202 K | 308 K | 128 | 118.3 | 104.5 | 86.1 |
| **C12** | Plain SPX | 20 | 7 | 20 | 8 | 45 | — | 6,512 B | 36.6 K | 276 K | — | — | 128 | 128 | 128 | 127.8 |
| **SLH-DSA-SHA2-128-24** | SLH-DSA-128-24 | 22 | 24 | 6 | 4 | 68 | — | 3,856 B | ~1.9 B SHA-256 | ~142 K* | — | — | 128 | 128 | 128 | 128 |
| **SLH-DSA-Keccak-128-24** | SLH-DSA-128-24 | 22 | 24 | 6 | 4 | 68 | — | 3,856 B | ~1.9 B keccak | ~94 K* | — | — | 128 | 128 | 128 | 128 |

- **Family**: the SPHINCS+ construction style (C-series WOTS+C/FORS+C with counter grinding; C12 plain SPX with plain WOTS+ checksum; SLH-DSA-128-24 with w=4, d=1 and a 2²⁴-sig hard cap).
- **sign_h**: hash-function calls during keygen + sign (determines signer speed). C-series + C12 use keccak256; SHA-2 SLH-DSA uses SHA-256.
- **swn**: small-Winternitz-number counter bits used by the WOTS+C / FORS+C grinding. Plain SPX and SLH-DSA don't counter-grind.
- **sec_N**: security bits at 2^N signatures per key. SLH-DSA-*-128-24 is flat 128-bit up to the **2²⁴ hard cap**, undefined beyond.
- **Verify (pure)**: Foundry `gasleft()` measurement of the assembly block. SLH-DSA-128-24 numbers (marked `*`) exclude tx base + calldata.
- **Frame**: total EIP-8141 frame-tx gas (ethrex). C12 / SLH-DSA-128-24 are not yet wired to frame accounts in this repo.
- **4337**: total ERC-4337 `handleOps` tx gas (Sepolia). Same caveat — the 4337 wiring for C7 / C11 lives in `SphincsAccount` + `SphincsAccountFactory`; no SLH-DSA or C12 account exists here yet.

C7 is the C-series gas champion with full 128-bit security up to 2²⁰ signatures. C11 is faster to sign (292 K hashes) but loses security after 2¹⁶ signatures. C12 has the lowest signer cost of all (36 K hashes — plain SPX with d=5 hypertree skips most tree-hash work) at the price of a 6,512-byte sig. SLH-DSA-SHA2-128-24 is the FIPS-aligned alternative: larger signer cost (~1.9 B hashes because d=1 forces a 2²² single XMSS tree), constant 128-bit security up to the 2²⁴ cap. The Keccak twin trades bit-exact NIST compliance for ~34 % cheaper on-chain verification — every F / H / T is a native `keccak256` opcode instead of a `staticcall(0x02)` to the SHA-256 precompile.

## Key Derivation

### BIP-39 Path (Rust WASM signer)

```
BIP-39 mnemonic (12 or 24 words)
    │
    ├──▶ HMAC-SHA512("sphincs-c6-v1", seed) → pkSeed, sk_seed (quantum-safe)
    └──▶ BIP-32 m/44'/60'/0'/0/0 → ECDSA address (independent)
```

SPHINCs- and ECDSA are derived through independent paths — compromising one does not compromise the other.

## Signers

| Signer | Language | Targets | BIP-39 |
|---|---|---|---|
| `script/signer.py` | Python | C-series (C7 / C9 / C11) | No |
| `signer-wasm/` | Rust/WASM | C-series | **Yes** |
| `script/slh_dsa_sha2_128_24_signer.py` | Python (slow; ~hours at NIST params) | SLH-DSA-SHA2-128-24 | No |
| `script/slh_dsa_keccak_128_24_signer.py` | Python (slow; ~hours at NIST params) | SLH-DSA-Keccak-128-24 | No |
| `signers/sphincsplus-128-24/` | C (forked from sphincs/sphincsplus ref) | SLH-DSA-SHA2-128-24 | No, seeds fed in |
| `signers/jardin-keccak-128-24/` | C (sphincsplus fork + custom keccak + 32-B ADRS) | SLH-DSA-Keccak-128-24 | No |

```bash
# Rust WASM C-series signer
cd signer-wasm && wasm-pack build --release --target web
cargo test --release -- --ignored

# SLH-DSA-128-24 fast C signers (~11 min per NIST-params sign on pure C, no SHA-NI)
(cd signers/sphincsplus-128-24  && make)
(cd signers/jardin-keccak-128-24 && make)
# Python wrapper with disk cache; Forge FFI tests use these:
python3 script/slh_dsa_sha2_128_24_fast_signer.py   <master_sk_hex> <message_hex>
python3 script/slh_dsa_keccak_128_24_fast_signer.py <master_sk_hex> <message_hex>
```

## Deployed Contracts & Transactions

EntryPoint v0.9: `0x433709009B8330FDa32311DF1C2AFA402eD8D009` (Sepolia)

### Sepolia (ERC-4337 Hybrid, C-series)

| Variant | Verifier | Account | Gas | Tx |
|---|---|---|---|---|
| C9 | [`0x18F005...`](https://sepolia.etherscan.io/address/0x18F005EECd41624644AA364bA8857258FEB3C26D) | [`0xA94111...`](https://sepolia.etherscan.io/address/0xA941116763AE386a50133c5af40356c9D93b2978) | 300 K | [`0x8366513b...`](https://sepolia.etherscan.io/tx/0x8366513b096ee53dd1cb105363ab21a52267dd966b822b4bb2cf5492abf1550f) |
| C11 | [`0xC25ef5...`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) | [`0x3C3b0c...`](https://sepolia.etherscan.io/address/0x3C3b0c3498E5ed9350F6fBFA0Ef8dC55f524eA50) | 308 K | [`0x9fba169c...`](https://sepolia.etherscan.io/tx/0x9fba169ca76b6712586e44e1a4a2d0407b8b8b9ce767272a193e41a756260b74) |

### Sepolia (SLH-DSA-128-24 standalone verifiers, no account wired yet)

| Variant | Verifier | Deploy tx | Sample verify tx | Verify-tx gas |
|---|---|---|---|---|
| SLH-DSA-SHA2-128-24 | [`0x9Fe417...`](https://sepolia.etherscan.io/address/0x9Fe41769395BC9fefb7e0d340064ed29F4a4Af91) | [`0x09be3c59...`](https://sepolia.etherscan.io/tx/0x09be3c5984ed99a93f9c43881822d9937e1efa9b31aee0630f59fca814d90e15) | [`0x00fa6b37...`](https://sepolia.etherscan.io/tx/0x00fa6b37347e2bedf37429a74563b2c68502becdffe3257ebde90f63e165030a) | **225,642** |
| SLH-DSA-Keccak-128-24 | [`0x2Ac9Ec...`](https://sepolia.etherscan.io/address/0x2Ac9Ec4a2A062aFc1be718e77ec3300D087E6205) | [`0x253aa6dc...`](https://sepolia.etherscan.io/tx/0x253aa6dc5c93a201abc7a5cfb4ce27cdeafb35e34fc69c23ef1daae0535c4c4a) | [`0x90d785a1...`](https://sepolia.etherscan.io/tx/0x90d785a112fd0198b4506caf432632777aef43b00ceb648e864dcb119311fed4) | **177,910** |

Verify-tx gas is the full top-level tx cost including 21 K tx base + ~63 K for the 3,872-B calldata payload; pure assembly execution is ~142 K (SHA-2) / ~94 K (Keccak). Keccak wins by ~21 % tx-level and ~34 % assembly-level because every F / H / T is a single native `keccak256` opcode, while the SHA-2 variant pays a `staticcall(0x02)` dispatch per hash × ~280 hashes.

### ethrex Testnet (EIP-8141 Frame Tx — Pure PQ)

Chain ID: 1729. VERIFY frame reads keys from storage, STATICCALLs shared verifier, APPROVEs. No ECDSA.

| Variant | Verifier | Frame Account | Gas | Verify | Tx |
|---|---|---|---|---|---|
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
# ── C-series (stateless hybrid + frame accounts) ───────────────────────────
# Deploy shared C-series verifier + SphincsAccountFactory (once):
forge script legacy/script/DeploySepolia.s.sol --rpc-url sepolia --broadcast

# Create account + send hybrid ERC-4337 UserOp (C7 / C11):
python3 legacy/script/send_userop.py create \
  --factory <factory> --ecdsa-key $PRIVATE_KEY --variant c7
python3 legacy/script/send_userop.py send \
  --account <account> --ecdsa-key $PRIVATE_KEY \
  --to <recipient> --value 0.001 --variant c7

# ── SLH-DSA-128-24 (standalone verifiers, no account) ──────────────────────
# Deploy both SLH-DSA verifiers to Sepolia:
forge script script/DeploySlhDsa128_24Sepolia.s.sol --rpc-url sepolia --broadcast

# Build the fast C signer (used by Forge FFI tests, ~11 min per NIST-params sign):
(cd signers/sphincsplus-128-24  && make)  # SHA-2 variant
(cd signers/jardin-keccak-128-24 && make) # Keccak variant

# Run the Forge end-to-end verify tests (first run triggers a real sign; later
# runs hit the disk cache at signers/*/\.cache/):
forge test --match-contract SLH_DSA_SHA2_128_24_Test   -vv
forge test --match-contract SLH_DSA_Keccak_128_24_Test -vv
```

## Tests

```bash
forge test
cd signer-wasm && cargo test --release -- --ignored
```

## Formal Verification (Lean 4 / Verity)

### Verified Kernel

This will include a proof with verity.
