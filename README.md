# SPHINCS- Post-Quantum Ethereum verifiers

---

> ## WARNING: RESEARCH PROTOTYPE - NOT FOR PRODUCTION USE
>
> This codebase is a scheme exploration for lightweight variants of SPHINCS+ (called SPHINCs-).
> It has **not been audited**, contains **no security guarantees**, and is
> **not safe to use with real funds**. Cryptographic parameters, key derivation,
> and contract logic have not been reviewed by any third party.
> **Use on testnets only.**

---
**Welcome to SPHINCs-**, a family of EVM-optimised variants of SLH-DSA and the recently proposed [SLH-DSA-SHA2-128-24](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-230.ipd.pdf). They all achieve low gas cost for pure on-chain signature verification without any precompile which makes them useful today without any ethereum hardfork. The key modifications is substituting SHAKE256 with the native keccak256 opcode and a significant reduction of the signature budget. NIST initially standardized a scheme with a 2^64 signature budget which is a huge number. Ethereum's on chain data shows that among 64,294,251 Ethereum mainnet addresses that sent at least one transaction in 2025 99.99% had less than 3000 transactions annually. The variants described in the repo give a trade-off between signing budget per key pair, verifier cost in gas and signer keygen and signing keccak calls (hardware wallet friendliness).

One can simply build a smart account using any of these verifiers, they are stateless and they maintain 128bits up their specified limits. For a efficient design that works on constrained device you can use the JARDÍN account design (A combination of SPHINCs- with a smaller compact path) are available for this. The SPHINCS+ registration path, the FORS compact path, all the JARDIN contracts and signers lives in a separate repo: [`nconsigny/JARDIN`](https://github.com/nconsigny/JARDIN).

---

## Variants

There are different ways to construct the SPHINCS signature scheme. Existing litterature shows various ways to optimise for signature size or verify cost. Active verifiers fall into three families:

- WOTS+C / FORS+C (ePrint 2025/2203), n=128-bit, d=2, domain-separated H_msg (160-byte hash). Signature-count cap = 2^h (C7 → 2²⁴, C11 → 2¹⁶); security degrades with N as shown in the `sec_N` columns below.
- Plain SPHINCS+ noted SPX with the JARDIN 32-byte ADRS kernel. n=128-bit, h=20, d=5, h'=4, plain WOTS+ checksum, keccak256 truncated to 128 bits. Design target: **128-bit classical security at q_s ≤ 2¹⁴** (≥ NIST Category I at the knee); degrades gracefully beyond - 109.1 bits at 2¹⁸, 95.4 bits at 2²⁰. Hypertree cap 2²⁰. (The JARDIN hybrid-account stack references this same contract as `JardinSpxVerifier` - see [`nconsigny/JARDIN`](https://github.com/nconsigny/JARDIN).)
- **SLH-DSA-128-24** - [NIST SP 800-230](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-230.ipd.pdf), n=128-bit, single-tree (d=1, h=22), w=4, **2²⁴ signature limit per key** (NIST hard cap, not just a security-degradation threshold), 3,856-byte signature.

| Variant | Family | h | d | a | k | w | l | swn | Sig | sign_h | Verify | Frame | 4337 | sec_10 | sec_14 | sec_18 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **C7** | WOTS+C / FORS+C | 24 | 2 | 16 | 8 | 8 | 43 | 151 | 3,704 B | 4.3 M | 127 K | 210 K | 318 K | 128 | 128 | 128 | 128 |
| **C11** | WOTS+C / FORS+C | 16 | 2 | 11 | 13 | 8 | 43 | 203 | 3,976 B | 292 K | 116 K | 202 K | 308 K | 128 | 128 | 104.5 | 86.1 |
| **C12** | vanilla SPHINCs+ | 20 | 5 | 7 | 20 | 8 | 45 | - | 6,512 B | 36.6 K | 276 K | - | - | 128 | 127.8 | 109.1 | 95.4 |
| **SLH-DSA-SHA2-128-24** | vanilla SPHINCs+ | 22 | 1 | 24 | 6 | 4 | 68 | - | 3,856 B | ~1.07 B | ~142 K* | - | - | 128 | 128 | 128 | 128 |
| **SLH-DSA-Keccak-128-24** | vanilla SPHINCs+ | 22 | 1 | 24 | 6 | 4 | 68 | - | 3,856 B | ~1.07 B | ~94 K* | - | - | 128 | 128 | 128 | 128 |

- **Family**: the SPHINCS+ construction style (vanilla SPHINCs+ SPX, WOTS +). WOTS+C / FORS+C is the C-series compact construction with counter-grinding (ePrint 2025/2203). Plain SLH-DSA / SPHINCS+ is the standard FIPS 205 construction with no counter grinding — C12 and the two SLH-DSA-128-24 entries are the same algorithm at different parameter sets, with the SHA-2 row using the FIPS 22-byte ADRSc + SHA-256 hash.
- **sign_h**: hash-function calls during keygen + one signature, zero-memory signer (no inter-sign caching — the relevant case for a hardware wallet). A high number means a lot of work for the hardware. C12 the lightest is ~40 sec to sign on secure element. 
- **swn**: small-Winternitz-number counter bits used by the WOTS+C / FORS+C grinding. Plain SPX and SLH-DSA don't counter-grind.
- **sec_N**: security bits at 2^N signatures per key. SLH-DSA-*-128-24 is flat 128-bit up to the **2²⁴ hard cap**, undefined beyond.
- **Verify (pure)**: Foundry `gasleft()` measurement of the assembly block. SLH-DSA-128-24 numbers (marked `*`) exclude tx base + calldata.
- **Frame**: total EIP-8141 frame-tx gas (ethrex). C12 / SLH-DSA-128-24 are not yet wired to frame accounts in this repo.
- **4337**: total ERC-4337 `handleOps` tx gas (Sepolia). The 4337 wiring for C7 / C11 lives in `SphincsAccount` + `SphincsAccountFactory`; no SLH-DSA or C12 account exists here yet.

C11 and C12 are light enough to run on a hardware wallet, 390s and 47.5s signature times on a ST33K1M5 secure element (Ledger nano S+). C12 has the lowest hardware signer cost of all (36 K hashes - plain SPX with d=5 hypertree skips most tree-hash work) at the price of a 6,512-byte sig. SLH-DSA-SHA2-128-24 is the FIPS-aligned alternative: much larger signer cost even on a desktop-class signer that caches the XMSS tree (~200 M hashes / sig, dominated by FORS — which can't be cached because the leaf-index to FORS-tree-address mapping changes with every message), and ~1.07 B / sig on a zero-memory signer that has to rebuild the 2²²-leaf XMSS for every auth path. Constant 128-bit security up to the 2²⁴ cap. The Keccak twin trades bit-exact NIST compliance for ~34 % cheaper on-chain verification (but not a very interesting trade-off as it keeps the same signer cost).

## Stateless SPHINCs- Architecture

### Shared hash kernel

The C-series, C12, and SLH-DSA-Keccak verifiers all share the **JARDIN kernel**: one 32-byte ADRS layout (`layer4‖tree8‖type4‖kp4‖ci4‖cp4‖ha4`) and one `keccak256` tweakable-hash shape (`keccak(seed32 ‖ adrs32 ‖ inputs)`). A device port covers those four variants with a single `sphincs_th*` implementation. **SLH-DSA-SHA2-128-24 is the outlier** - it sticks to the FIPS 205 22-byte compressed ADRSc and SHA-256 (with the nested MGF1-based Hmsg), so it needs its own primitive set. **ADRSc** (`layer(1) ‖ tree(8) ‖ type(1) ‖ 12 B type-dependent`), SHA-256 primitive, F / H / T input = `PK.seed(16) ‖ zeros(48) ‖ ADRSc(22) ‖ payload`, nested `Hmsg = MGF1-SHA-256(R ‖ seed ‖ SHA-256(R ‖ seed ‖ root ‖ M), m=21)`, byte-wise LSB-first digest-to-indices (same convention as the sphincs/sphincsplus reference and PQClean).

For the **SLH-DSA-128-24** family we have two wire-level layouts:
  - **SHA-2 variant** - FIPS 205 bit-exact:
  - **Keccak variant** - JARDIN twin: 32-byte full ADRS (`layer4 ‖ tree8 ‖ type4 ‖ kp4 ‖ ci4 ‖ cp4 ‖ ha4`), keccak256 primitive, F / H / T input = `seed32 ‖ adrs32 ‖ payload`, one-shot `Hmsg = keccak(seed ‖ root ‖ R ‖ msg ‖ 0xFF..FB)` (no MGF1), LSB-first digest-to-indices on the 256-bit keccak output interpreted as a single big-endian integer.

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

The frame account has keys baked into its bytecode - no storage, no calldata overhead for keys. It receives `sigHash + raw_sig`, builds the full ABI call to the shared verifier internally, and calls APPROVE on success.

```
Frame Transaction (type 0x06)
    ├── Frame 0 (VERIFY): frame account builds verify(pkSeed, pkRoot, sigHash, sig)
    │     from embedded keys + calldata → STATICCALLs shared verifier → APPROVE
    └── Frame 1 (SENDER): ETH transfer / contract call
```
No ECDSA - pure post-quantum. Keys are stored in EVM storage (not bytecode) to support future key rotation via `rotateKeys()` - costs ~4K gas per verify but keeps the same account address across key changes.

## Key Derivation

### BIP-39 Path (Rust WASM signer)

```
BIP-39 mnemonic (12 or 24 words)
    │
    ├──▶ HMAC-SHA512("sphincs-c6-v1", seed) → pkSeed, sk_seed (quantum-safe)
    └──▶ BIP-32 m/44'/60'/0'/0/0 → ECDSA address (independent)
```

SPHINCs- and ECDSA are derived through independent paths - compromising one does not compromise the other.

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

### ethrex Testnet (EIP-8141 Frame Tx - Pure PQ)

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
