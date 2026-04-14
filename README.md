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

Post-quantum signature verification on Ethereum using SPHINCs- — lightweight hash-based signatures derived from SPHINCS+. Supports JARDÍN hybrid accounts (ECDSA + SPHINCs-), stateless ERC-4337 accounts, and native EIP-8141 frame transaction accounts (pure PQ).

## JARDÍN — Compact + Stateless Hybrid Account

**JARDÍN** (Judicious Authentication from Random-subset Domain-separated Indexed Nodes) is a two-lane post-quantum account:

1. **Register once** — sign one expensive stateless SPHINCs- C11 signature to open a "slot" (a lane of 95 cheap signatures)
2. **Use the lane** — every subsequent transaction uses a compact FORS+C few-time signature at ~49K verify gas, growing by ~500 gas per use
3. **Lane exhausted?** — after 95 uses, register a new slot. The old lane is done; the new one starts fresh

This gives you **95 cheap transactions for every 1 expensive registration**. A regular user rotating slots every 95 txs pays the stateless price only ~1% of the time.

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Type 1 (register)         Type 2 (compact, ×95)        Type 1 …  │
  │  ████████████████           ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ████…    │
  │  C11 stateless             FORS+C few-time               new slot  │
  │  323K gas, once            117K–163K gas, every tx        289K gas  │
  └─────────────────────────────────────────────────────────────────────┘
```

Both ERC-4337 (hybrid ECDSA + PQ on Sepolia) and EIP-8141 frame transactions (pure PQ on ethrex) are supported. The frame path uses a 67-byte hand-optimized proxy with TXPARAM-aware APPROVE.

```
C11 Verifier (stateless, shared)       JardinForsCVerifier (compact, shared)
    ↑ verify(...)                           ↑ verifyForsCUnbalanced(...)
    │                                       │
    └──── Type 1 (ECDSA + C11) ────────────┘──── Type 2 (ECDSA + FORS+C)
                       │
                  JardinAccount (ERC-4337, hybrid)
                  ├── owner (ECDSA, rotatable)
                  ├── masterPkSeed, masterPkRoot (C11 identity)
                  ├── slots: mapping(H(r) → H(subPkSeed, subPkRoot))
                  ├── Type 1: device registration + C11 fallback (once per slot)
                  └── Type 2: FORS+C compact path (every subsequent tx)
```

### JARDIN (compact path FORS+C) Parameters

| Parameter | Value |
|-----------|-------|
| k (FORS trees) | 26 |
| a (tree height) | 5 (32 leaves per tree) |
| n (hash output) | 16 bytes (128-bit) |
| k×a (security bits) | 130 |
| Q_MAX (leaves per slot) | 95 |
| Keygen (D=95) | ~235K hashes (~2.3s Python) |
| **Pure Verify cost** | **48K** |
| **Frame transaction** | **117K** |
| ERC 4337 | 173 K |

### Signature Types

**Stateless SPHINCS- (Type 1)** — ECDSA + Stateless C11 + optional sub-key registration:
```
[0x01][ecdsaSig 65B][r 32B][subPkSeed 16B][subPkRoot 16B][C11 sig ~3976B] = ~4,138 bytes
```

**SHRINCS FORS+C (Type 2)** — ECDSA + FORS+C compact via registered sub-key slot:
```
[0x02][ecdsaSig 65B][H(r) 32B][subPkSeed 16B][subPkRoot 16B][FORS+C sig] = ~2,598 bytes (q=1)
```

The FORS+C signature grows by 16 bytes per use (one unbalanced tree auth node): 2,598 B at q=1, 4,102 B at q=95. At q=95 the compact sig (3,972 B) nearly equals the C11 stateless sig (3,976 B) — the natural crossover. After Q_MAX uses, register a new slot via Type 1.

### Key Derivation & The Random Slot `r`

Everything derives from a single **24-word BIP-39 mnemonic**. The derivation splits into two independent quantum-safe paths:

```
BIP-39 mnemonic (24 words)
    │
    ├── HMAC-SHA512("sphincs-c11-v1", bip39_seed)
    │       │
    │       ├── masterPkSeed (16 bytes) ── on-chain, in JardinAccount
    │       ├── masterPkRoot (16 bytes) ── on-chain, C11 hypertree root
    │       └── masterSkSeed (32 bytes) ── secret, derives everything else
    │
    └── BIP-32 m/44'/60'/0'/0/0 ── ECDSA address (independent, standard Ethereum path)
```

The **on-chain identity is the contract address** (deterministic via CREATE2 from the factory). The master C11 key authenticates Type 1 signatures and can be rotated via `rotateMasterKeys()` — the account address stays the same.

**The random `r`** is where FORS+C sub-keys come from. Each device (or slot rotation) generates a fresh 32-byte random `r` using its hardware RNG:

```
r = hardware_rng(32)                                    ← 2^256 space, no collision possible
sub_sk_seed = HMAC-SHA512(masterSkSeed, r)              ← deterministic from master + r
sub_pk_seed, sub_pk_root = FORS+C_keygen(sub_sk_seed)   ← unbalanced tree of Q_MAX FORS+C keys
```

The contract stores `slots[keccak256(r)] = keccak256(subPkSeed, subPkRoot)`. The slot key is `H(r)`, not `r` itself — the raw `r` is only revealed once during registration (Type 1) and never reused. This means:

- **`r` is ephemeral device state** — lost on backup restore, regenerated per device
- **`H(r)` is the on-chain slot identifier** — maps to the sub-key commitment
- **The master seed is the only backup** — 24 words recover the master key; each device generates its own `r`

### Multi-Device Flow

```
WALLET CREATION (one-time):
  1. Generate 24-word BIP-39 mnemonic
  2. Derive master C11 keypair via HMAC-SHA512
  3. Deploy JardinAccount via factory → contract address is your on-chain identity

     The address is deterministic (CREATE2):
       address = keccak256(0xff ‖ factory ‖ salt ‖ initCodeHash)
       salt    = keccak256(owner ‖ masterPkSeed ‖ masterPkRoot)

     Same inputs always produce the same address, even before deployment.
     Keys can be rotated later; the address never changes.

DEVICE A (first use):
  1. Derive master keys from seed
  2. r_A = hardware_rng(32)                                    ← random, local to device
  3. Derive FORS+C sub-key from HMAC(masterSkSeed, r_A)
  4. Type 1 UserOp: C11 signs + registers slots[H(r_A)]       ← 323K gas, once
  5. Type 2 UserOps: FORS+C signs at q=1,2,...,95              ← 173K gas, every tx
  6. Slot exhausted → new r, Type 1 registers new slot         ← 289K gas, every 95 txs

DEVICE B (independent, same seed):
  1. Same master keys from same 24 words
  2. r_B = hardware_rng(32)                                    ← different from r_A, P(collision) = 2^-256
  3. Independent FORS+C sub-key from HMAC(masterSkSeed, r_B)
  4. Type 1 registers slots[H(r_B)] — no coordination with Device A
  5. Type 2 at its own q counter — fully independent

DEVICE A LOST, restored on DEVICE C:
  1. Enter 24 words → recovers master keys
  2. r_C = hardware_rng(32)                                    ← new slot, old r_A is lost
  3. Type 1 registers slots[H(r_C)] — orphaned slot H(r_A) is harmless
  4. Type 2 resumes on new slot

EMERGENCY (device has seed but no FORS+C state):
  1. Type 1 with r = 0x00..0 (no registration flag)
  2. Pure stateless C11 sig — works immediately, no slot needed
  3. 323K gas, 4,138 bytes — expensive but always available
```

### Measured Gas — 98/98 on-chain transactions (Q_MAX=95)

**Sepolia (ERC-4337 hybrid ECDSA + PQ)** and **ethrex (EIP-8141 frame tx, pure PQ)**, full slot exhaustion + re-registration:

| Event | Sig Size | Frame (ethrex) | 4337 (Sepolia) | Frequency |
|-------|----------|---------------|----------------|-----------|
| Device registration (Type 1) | 4,041 / 4,138 B | **235K** | **323K** | Once per 95 txs |
| Compact q=1 (Type 2) | 2,468 / 2,598 B | **117K** | **173K** | Every tx |
| Compact q=32 (Type 2) | 2,964 / 3,094 B | **132K** | **188K** | |
| Compact q=95 (Type 2) | 3,972 / 4,102 B | **163K** | **219K** | Last before rotation |
| Re-registration (Type 1) | 4,041 / 4,138 B | **235K** | **289K** | New slot |
| New slot q=1 (Type 2) | 2,468 / 2,598 B | **117K** | **173K** | Back to compact |

| Metric | Frame (ethrex) | 4337 (Sepolia) |
|--------|---------------|----------------|
| Total txs | 98/98 success | 98/98 success |
| Type 2 average | **140K** | **196K** |
| Per-q increment | ~498 gas | ~498 gas |
| 4337 overhead | — | ~56K constant (EntryPoint + ECDSA) |
| C11 crossover | q=95 (3,972B vs 3,976B) | q=95 (4,102B vs 4,138B) |

Gas per q increment: ~498 gas avg. Compact path saves **44%** gas vs stateless C11 at q=1, **22%** at q=95.

### Security

| Property | Value |
|----------|-------|
| Compact path r=1 | 128-bit (normal) |
| Compact path r=2 (double-sign) | 105-bit (graceful degradation) |
| Fallback (C11) at 2^14 sigs | 128-bit |
| Hash function | keccak256 (native EVM) |
| Post-quantum | Yes (hash-only security) |

No on-chain leaf counter. The leaf index q is derived from the signature length. FORS+C's few-time nature tolerates accidental double-signing. Replay protection comes from the EntryPoint nonce (4337) or Frame protocol nonce.

### Deployed

**Sepolia (ERC-4337 hybrid ECDSA + PQ):**

| Contract | Address |
|----------|---------|
| JARDÍN FORS+C Verifier | [`0xFAFcbEfa...`](https://sepolia.etherscan.io/address/0xFAFcbEfa48795E3C05b2ee2Df305B8685A839d9E) |
| JARDÍN Account Factory | [`0xFF3cF63D...`](https://sepolia.etherscan.io/address/0xFF3cF63De35e5aa3382A2086b7E0C96031607d52) |
| JARDÍN Account (98 UserOps) | [`0x358e523f...`](https://sepolia.etherscan.io/address/0x358e523fE4644083AB56eA74Deda6593442600B9) |
| SPHINCs- C11 Verifier (shared) | [`0xC25ef566...`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) |

**ethrex (EIP-8141 frame tx, pure PQ):**

| Contract | Address |
|----------|---------|
| JARDÍN Frame Proxy (67 bytes) | `0x94fFA1C7330845646CE9128450F8e6c3B5e44F86` |
| JARDÍN Frame Impl | `0x8ac87219a0f5639bc01b470f87ba2b26356cb2b9` |
| JARDÍN FORS+C Verifier | `0x56d13eb21a625eda8438f55df2c31dc3632034f5` |
| SPHINCs- C11 Verifier | `0x3155755b79aA083bd953911C92705B7aA82a18F9` |

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

All SPHINCs- variants use WOTS+C / FORS+C (ePrint 2025/2203), n=128-bit, d=2, domain-separated H_msg (160-byte hash).

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

SPHINCs- and ECDSA are derived through independent paths — compromising one does not compromise the other.

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
