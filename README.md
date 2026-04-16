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
| C9 | [`0x18F005...`](https://sepolia.etherscan.io/address/0x18F005EECd41624644AA364bA8857258FEB3C26D) | [`0xA94111...`](https://sepolia.etherscan.io/address/0xA941116763AE386a50133c5af40356c9D93b2978) | 300K | [`0x8366513b...`](https://sepolia.etherscan.io/tx/0x8366513b096ee53dd1cb105363ab21a52267dd966b822b4bb2cf5492abf1550f) |

| C11 | [`0xC25ef5...`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) | [`0x3C3b0c...`](https://sepolia.etherscan.io/address/0x3C3b0c3498E5ed9350F6fBFA0Ef8dC55f524eA50) | 308K | [`0x9fba169c...`](https://sepolia.etherscan.io/tx/0x9fba169ca76b6712586e44e1a4a2d0407b8b8b9ce767272a193e41a756260b74) |

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

This will include a proof with verity 





## JARDÍN — Compact + Stateless Hybrid Account

**JARDÍN** (Judicious Authentication from Random-subset Domain-separated Indexed Nodes) is a post-quantum smart account. It combines the stateless SPHINCs- scheme with a second verifier — a balanced Merkle tree of FORS+C instances (height h=7, Q_MAX=128) on the "compact" lane. Together they form a multi-lane architecture:

1. **Register once** — sign one expensive stateless SPHINCs- C11 signature to open a "slot" (a lane of 128 cheap signatures)
2. **Use the lane** — every subsequent transaction uses a compact FORS+C few-time signature at constant ~49K verify gas (any q)
3. **Lane exhausted?** — after 128 uses, register a new slot. The old lane is done; the new one starts fresh

This gives you **128 cheap transactions for every 1 expensive registration**. A regular user rotating slots every 128 txs pays the stateless price less than 1% of the time. The stateless C11 fallback is always available — no slot needed, no state needed, just the 24-word seed.

```
1st Tx        128 Tx                                     2nd Tx
Register     JARDÍN (FORS+C compact, x128)               Register
  ┌──────┐  ┌─────────────────────────────────────────┐  ┌──────┐
  │ C11  │->│  q=1    q=2    q=3   ...   q=127  q=128 │->│ C11  │  ...
  │ 235K │->│  119K   119K   119K  ...   119K   119K  │->│ 235K │
  └──────┘  └─────────────────────────────────────────┘  └──────┘
  Stateless C11 fallback: always available (209K gas)
  Gas numbers: EIP-8141 frame transactions (ethrex). ERC-4337 adds ~56K overhead.
```

Both ERC-4337 (hybrid ECDSA + PQ on Sepolia) and EIP-8141 frame transactions (pure PQ on ethrex) are supported. The frame path uses a 67-byte hand-optimized proxy with TXPARAM-aware APPROVE.

```
C11 Verifier (stateless, shared)       JardinForsCVerifier (compact, shared)
    ↑ verify(...)                           ↑ verifyForsC(...)
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
| h (balanced Merkle height) | 7 |
| Q_MAX (leaves per slot) | 128 |
| Keygen (Q=128) | ~316K hashes |
| **Pure Verify cost** | **~49K** |
| **Frame transaction** | **~119K (constant)** |
| ERC 4337 | ~176K (constant) |

### Signature Types

**Stateless SPHINCS- (Type 1)** — ECDSA + Stateless C11 + optional sub-key registration:
```
[0x01][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][C11 sig ~3976B] = ~4,106 bytes
```
If `subPkSeed == 0 && subPkRoot == 0`, registration is skipped (stateless fallback).

**FORS+C (Type 2)** — ECDSA + FORS+C compact via registered sub-key slot:
```
[0x02][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][FORS+C sig 2565B] = ~2,663 bytes (constant)
```
Slot key is `keccak256(subPkSeed, subPkRoot)` — no `r` or `H(r)` on-chain.

The FORS+C signature is a constant ~2,598 bytes for every q (the balanced h=7 Merkle auth path is always 7 nodes = 112 bytes, plus a 1-byte explicit `q` field). After Q_MAX uses, register a new slot via Type 1.

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
sub_pk_seed, sub_pk_root = FORS+C_keygen(sub_sk_seed)   ← balanced h=7 tree of Q_MAX=128 FORS+C keys
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

### Measured Gas — balanced h=7 tree, Q_MAX=128

**Sepolia (ERC-4337 hybrid ECDSA + PQ)** and **ethrex (EIP-8141 frame tx, pure PQ)**, full slot exhaustion + re-registration. Compact-path gas is now constant across all q (balanced tree ⇒ constant 7-node auth path):

| Event | Sig Size | Frame (ethrex) | 4337 (Sepolia) | Frequency |
|-------|----------|---------------|----------------|-----------|
| Device registration (Type 1) | 4,041 / 4,138 B | **234K** | **323K** | Once per 128 txs |
| Compact (Type 2, any q) | 2,533 / 2,598 B | **119K** | **176K** | Every tx |
| Stateless fallback (Type 1, r=0) | 4,009 / 4,106 B | **209K** | **300K** | Emergency |
| Re-registration (Type 1) | 4,041 / 4,138 B | **234K** | **289K** | New slot |

| Metric | Frame (ethrex) | 4337 (Sepolia) |
|--------|---------------|----------------|
| Type 2 gas | **119K (constant)** | **176K (constant)** |
| Per-q increment | 0 (balanced tree) | 0 (balanced tree) |
| 4337 overhead | — | ~56K constant (EntryPoint + ECDSA) |

Gas per q increment: ~498 gas avg. Compact path saves **44%** gas vs stateless C11 at q=1, **22%** at q=95.

### Security

| Property | Value |
|----------|-------|
| Compact path r=1 | 128-bit (normal) |
| Compact path r=2 (double-sign) | 105-bit (graceful degradation) |
| Fallback (C11) at 2^14 sigs | 128-bit |
| Hash function | keccak256 (native EVM) |
| Post-quantum | Yes (hash-only security) |

No on-chain leaf counter. The leaf index q is encoded as a 1-byte explicit field in the FORS+C signature. Slot key is `keccak256(subPkSeed, subPkRoot)` — the random `r` used to derive the sub-key never appears on-chain. FORS+C's few-time nature tolerates accidental double-signing (105-bit at r=2). Replay protection comes from the EntryPoint nonce (4337) or Frame protocol nonce.

### Deployed (balanced h=7 tree, Q_MAX=128)

**Sepolia (ERC-4337 hybrid ECDSA + PQ):**

| Contract | Address |
|----------|---------|
| JARDÍN FORS+C Verifier | [`0xef0f8def...`](https://sepolia.etherscan.io/address/0xef0f8def0caef9863b4061d6f2397d7d57c9bdfc) |
| JARDÍN Account Factory | [`0x9ff19a7d...`](https://sepolia.etherscan.io/address/0x9ff19a7d8e438b59f1f0f892caa004784f491e65) |
| JARDÍN Account (65 UserOps via Candide bundler) | [`0x0b0083c9...`](https://sepolia.etherscan.io/address/0x0b0083c930A5613E1391144edb132d8A75aa3DBb) |
| SPHINCs- C11 Verifier (shared) | [`0xC25ef566...`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) |

**ethrex (EIP-8141 frame tx, pure PQ):**

| Contract | Address |
|----------|---------|
| JARDÍN Frame Proxy (67 bytes) | `0x627b9A657eac8c3463AD17009a424dFE3FDbd0b1` |
| JARDÍN Frame Impl | `0x5Ffe31E4676D3466268e28a75E51d1eFa4298620` |
| JARDÍN FORS+C Verifier | `0x4eaB29997D332A666c3C366217Ab177cF9A7C436` |
| SPHINCs- C11 Verifier | `0x3155755b79aA083bd953911C92705B7aA82a18F9` |

Full slot cycle (register → 128 compact → re-register → 1 compact in new slot) completed on both chains with 0 failures on the ethrex frame path and 20/20 success on the Candide-bundled Sepolia path.



## References

- [ePrint 2025/2203](https://eprint.iacr.org/2025/2203) — Blockstream SPHINCS+ parameter optimization (WOTS+C, FORS+C)
- [SPHINCS-Parameters](https://github.com/nconsigny/SPHINCS-Parameters) — EVM-adapted parameter search with calibrated gas model
- [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) — Frame transactions (native account abstraction) 
- [Verity](https://github.com/Th0rgal/verity) — Lean 4 → EVM formally verified smart contracts
- [ZKnox/Kohaku](https://github.com/ethereum/kohaku) — PQ account pattern (shared verifier model)
