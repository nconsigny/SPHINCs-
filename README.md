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

Post-quantum signature verification on Ethereum using SPHINCs- — lightweight hash-based signatures derived from SPHINCS+. Supports JARDÍN hybrid accounts (ECDSA + SPHINCs-) with a plain-SPHINCS+ (SPX) registration path and a balanced-tree FORS+C compact path, stateless ERC-4337 accounts, and native EIP-8141 frame transaction accounts (pure PQ).

For the full JARDÍN design write-up, see [`writeUp.md`](./writeUp.md).

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

This will include a proof with verity.

---

# JARDÍN — Compact + Stateless Hybrid Account

**JARDÍN** (Judicious Authentication from Random-subset Domain-separated Indexed Nodes) is a post-quantum smart account that combines the stateless SPHINCs- scheme with a second verifier — a **balanced Merkle tree** of FORS+C few-time instances (height `h=7`, `Q_MAX=128`) on the "compact" lane. Together they form a two-lane architecture:

1. **Register once** — one expensive stateless SPHINCs- C11 signature opens a "slot": a lane of 128 cheap signatures.
2. **Use the lane** — every subsequent transaction uses a compact FORS+C signature at **constant** ~49K verify gas regardless of `q`.
3. **Lane exhausted?** — after 128 uses the device generates a fresh random `r`, derives a new sub-key, and registers a new slot. The old lane is done; the new one starts fresh.

128 cheap transactions for every 1 expensive registration. A user who rotates slots every 128 txs pays the stateless price <1 % of the time. The stateless C11 fallback is always available — no slot needed, no device state needed, just the 24-word seed.

```
 Register           JARDÍN (FORS+C compact, ×128 constant-gas)          Register        …
  ┌──────┐  ┌─────────────────────────────────────────────────┐  ┌──────┐
  │ C11  │→│  q=1   q=2   q=3  …  q=63  q=64  …  q=127  q=128 │→│ C11  │  …
  │ 235K │→│  119K  119K  119K …  119K  119K  …  119K   119K  │→│ 235K │
  └──────┘  └─────────────────────────────────────────────────┘  └──────┘
  Stateless C11 fallback: always available (209 K gas)
  Gas numbers: EIP-8141 frame transactions (ethrex). ERC-4337 adds ~56 K overhead.
```

Both ERC-4337 (hybrid ECDSA + PQ on Sepolia) and EIP-8141 frame transactions (pure PQ on ethrex) are supported. The frame path uses a 67-byte hand-optimized proxy with TXPARAM-aware APPROVE.

## Architecture

```
SPHINCs- C11 Verifier (stateless, shared)     JardinForsCVerifier (compact, shared)
        ↑ verify(pkSeed, pkRoot, msg, sig)             ↑ verifyForsC(subSeed, subRoot, msg, sig)
        │                                              │
        └────── Type 1 (ECDSA + C11) ─────────────────┘── Type 2 (ECDSA + FORS+C)
                               │
                     JardinAccount (ERC-4337, hybrid)
                     ├── owner                  (ECDSA signer, rotatable)
                     ├── masterPkSeed / masterPkRoot (C11 identity, rotatable)
                     └── slots: mapping(keccak256(subPkSeed, subPkRoot) ⇒ uint256)
                                     │
                                     ├── Type 1:  registers the sub-key (slot ← 1)
                                     │           OR acts as stateless fallback
                                     │           when subPkSeed == subPkRoot == 0
                                     └── Type 2:  slots[H(subPkSeed, subPkRoot)] ≠ 0
                                                  required; no r / no H(r) on-chain
```

The on-chain contract **does not know `r`**. The device-local random `r` derives the sub-key off-chain; the contract only ever sees the sub-key's public components (`subPkSeed`, `subPkRoot`), and identifies the slot by `keccak256(subPkSeed, subPkRoot)`. Since those public components are already present in every Type 2 signature for FORS+C verification, the signature carries **no extra bytes** for slot lookup.

## Compact-Path Parameters

| Parameter | Value | Rationale |
|---|---|---|
| k (FORS trees) | 26 | k × a = 130 ≥ 128 for one-time security |
| a (tree height) | 5 (32 leaves / tree) | Minimises signing cost (~2,600 hashes) |
| n (hash output) | 16 bytes | 128-bit hash |
| h (balanced Merkle height) | 7 | Q_MAX = 2^h = 128 |
| k_open | 25 | FORS+C removes the last tree; ~32 counter grinds |
| Keygen (per slot, 128 leaves) | ~316 K keccak | ~3 s Python / ~5 min secure element |
| **Verifier gas (pure)** | **~49 K (constant)** | 128-bit masked keccak, balanced h = 7 walk |
| **Frame transaction** | **~119 K (constant)** | EIP-8141 type 0x06 |
| **ERC-4337 UserOp** | **~176 K (constant)** | EntryPoint v0.9 + ECDSA overhead |

## Signature Types

**Type 1 (stateless C11 + optional registration)** — signs any message with the master C11 key, and *optionally* registers a new sub-key in the same UserOp:
```
[0x01][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][C11 sig ~3,976B] ≈ 4,106 B
```
If `subPkSeed == 0 && subPkRoot == 0`, registration is **skipped** — this is the stateless fallback path (always available, no slot needed).

**Type 2 (FORS+C compact)** — requires a registered slot:
```
[0x02][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][FORS+C body 2,452B][q 1B][merkleAuth 112B]
                                                  └────────── FORS+C sig 2,565 B (constant) ──────────┘
= 2,663 B total (constant across q)
```

The FORS+C sig is **constant 2,565 bytes** for every `q`:
- `R (32) + counter (4) + 25 × (secret 16 + auth 5×16) + lastRoot (16)` = 2,452 B FORS+C body
- `+ q (1 byte, explicit)` — never on-chain, only in the sig; the verifier reads it directly
- `+ 7-node Merkle auth path (7 × 16 = 112 B)` — always 7 nodes thanks to the balanced tree

A wrong `q` produces a wrong FORS+C public key (via `ci = q` domain separation in the FORS ADRS), which produces a wrong balanced-tree root, which fails the root check. The signer cannot lie about `q`.

## Slot Key & Multi-Device Flow

**Slot key is `keccak256(subPkSeed, subPkRoot)`** — the sub-key's public commitment. The random `r` used to derive the sub-key **never appears on-chain**.

```
BIP-39 mnemonic (24 words)
    │
    ├── HMAC-SHA512("sphincs-c11-v1", seed)
    │        ├── masterPkSeed, masterPkRoot  ← on-chain C11 identity
    │        └── masterSkSeed                ← master secret
    │
    └── BIP-32 m/44'/60'/0'/0/0             ← ECDSA signer address (independent)

Per device, per slot (rotated after Q_MAX=128 compact sigs):
    r = hardware_rng(32)                                 ← 2^256 space, P(collision) = 2^-256
    sub_sk_seed = HMAC-SHA512(masterSkSeed, r)           ← deterministic from master + r
    sub_pk_seed, sub_pk_root = FORS+C_keygen(sub_sk_seed)← balanced h=7 tree of 128 keys

    Type 1 registers slots[keccak256(subPkSeed, subPkRoot)] ← 1   (the random r stays on-device)
```

Why random, not derived: if `r` were `HMAC(masterSkSeed, device_index)`, two devices restored from the same 24 words would share a sub-key, and every overlapping `q` would be a double-signing event. A fresh hardware-RNG `r` per device makes sub-key collisions negligible.

```
DEVICE A (first use):
  1. Derive master C11 keys from 24-word seed
  2. r_A = hardware_rng(32)
  3. Derive FORS+C sub-key (sub_pk_seed_A, sub_pk_root_A)
  4. Type 1 UserOp: C11 signs + registers slots[H(sub_pk_seed_A, sub_pk_root_A)] ← 323K gas, once
  5. Type 2 UserOps: FORS+C signs at q = 1, 2, …, 128                             ← 176K gas, every tx
  6. Slot exhausted → fresh r, Type 1 registers a new slot                         ← 289K gas

DEVICE B (independent, same 24 words):
  1. Same master keys
  2. r_B = hardware_rng(32)                                                        ← different from r_A
  3. Independent FORS+C sub-key
  4. Type 1 registers slots[H(sub_pk_seed_B, sub_pk_root_B)] — no coord with A
  5. Type 2 at its own q counter, fully independent

DEVICE A LOST, restored on DEVICE C:
  1. Enter 24 words → master keys recovered
  2. r_C = hardware_rng(32)                                                        ← new, r_A is lost
  3. Type 1 registers slots[H(sub_pk_seed_C, sub_pk_root_C)]
  4. Orphaned slots (A's and B's) are harmless — no attacker has their sub_sk_seed

EMERGENCY (device has seed but no FORS+C state):
  1. Type 1 with subPkSeed = subPkRoot = 0 (skips registration)
  2. Pure stateless C11 sig — works immediately, no slot needed
  3. ~300K gas, ~4,106 bytes — expensive but always available
```

**Unlimited devices from a single 24-word mnemonic**: each device picks its own 256-bit random `r`, so collisions between devices occur with probability 2^-256. No inter-device coordination is needed.

## Anti-Rollback (Burn-Before-Sign)

Because FORS+C provides only **few-time** security, the signer must never re-use `q` for different messages. The hardware wallet implementation follows burn-before-sign:

1. Host sends `SIGN_INIT(q, message_hash)`.
2. Device shows an NBGL confirmation screen ("Sign with JARDÍN? Leaf q=N"). User approves.
3. Device **increments `q` in NVRAM** via `nvm_write()` ← BURN.
4. Device computes the FORS+C signature ← SIGN.
5. Device returns the signature chunks over USB.

If the device crashes after step 3, one leaf is wasted; if it crashes during step 4 or 5, `q` is still consumed and the next signature uses `q+1`. **The leaf is never signed twice** in normal operation, and FORS+C's graceful degradation (105-bit at r=2) remains a safety net for state-corruption edge cases.

## Measured Gas — balanced h=7 tree, Q_MAX=128

Full slot cycle (Type 1 register → 128 × Type 2 → Type 1 re-register → Type 2 in new slot) completed on both chains. Compact-path gas is **constant** across every `q` — the balanced tree has a 7-node auth path regardless of leaf index.

| Event | Sig Size (frame / 4337) | Frame (ethrex) | 4337 (Sepolia) | Frequency |
|---|---|---|---|---|
| Device registration (Type 1) | 4,041 B / 4,106 B | **234 K** | **323 K** | Once per 128 txs |
| Compact (Type 2, any q) | 2,598 B / 2,663 B | **119 K (const.)** | **176 K (const.)** | Every tx |
| Stateless fallback (Type 1, sub=0) | 4,009 B / 4,106 B | **209 K** | **300 K** | Emergency |
| Re-registration (Type 1) | 4,041 B / 4,106 B | **234 K** | **289 K** | New slot |

| Metric | Frame (ethrex) | 4337 (Sepolia) |
|---|---|---|
| Type 2 per-q increment | 0 (balanced tree) | 0 (balanced tree) |
| 4337 overhead | — | ~56 K constant (EntryPoint + ECDSA) |

Compact path vs stateless C11: **~44 % less gas, constant across all q** (the old unbalanced-spine design grew linearly — 16 B / ~500 gas per `q`).

## Security Summary

| Component | Property | Value |
|---|---|---|
| Compact path (FORS+C k=26, a=5) | One-time (r=1) | **130-bit** |
|   | Double-sign (r=2) | 105-bit (graceful) |
|   | Five reuses (r=5) | 74-bit |
| Stateless fallback (SPHINCs- C11) | At 2^14 sigs | 128-bit |
|   | At 2^18 sigs | 104.5-bit |
| Hybrid ECDSA (4337) | Pre-quantum | secp256k1 |
| Hash function | Preimage | keccak256, 128-bit |
| Replay protection | 4337 | EntryPoint nonce |
|   | Frame | Protocol nonce |
| Rollback resistance | Device | Burn-before-sign (NVRAM) |

The master C11 key signs **only Type 1 events** (registration + re-registration + emergency). With `Q_MAX = 128`, a wallet producing 100,000 compact signatures needs only ~782 C11 signatures — well within the 2^14 128-bit-safe zone.

The hybrid ECDSA requirement (ERC-4337 path) means the scheme is at least as secure as the stronger of ECDSA and SPHINCs- today, and remains secure under either classical or quantum attacks. The frame account (EIP-8141) drops ECDSA for a pure post-quantum path.

## ADRS Scheme (32 bytes)

```
layer(4) ‖ tree(8) ‖ type(4) ‖ kp(4) ‖ ci(4) ‖ x(4) ‖ y(4)

type = 3  FORS_TREE        kp=0  ci=q  x=treeHeight  y=treeIndex (continuous across k trees)
type = 4  FORS_ROOTS       kp=0  ci=q  x=0           y=0
type = 6  FORS_PRF         kp=0  ci=q  x=0           y=treeIndex
type = 16 JARDIN_MERKLE    kp=0  ci=0  x=level       y=nodeIndex
```

- `ci = q` in the FORS types provides domain separation between compact-path instances at different balanced-tree leaf positions.
- `JARDIN_MERKLE` (type 16) is outside the FIPS 205 range and handles the balanced outer tree only.
- `setTypeAndClear(type)` is called whenever `type` changes; all other fields are set explicitly.

## Deployed

**Sepolia (ERC-4337 hybrid ECDSA + PQ)** — balanced h=7, Q_MAX=128:

| Contract | Address |
|---|---|
| JARDÍN FORS+C Verifier | [`0xef0f8def…`](https://sepolia.etherscan.io/address/0xef0f8def0caef9863b4061d6f2397d7d57c9bdfc) |
| JARDÍN Account Factory | [`0x9ff19a7d…`](https://sepolia.etherscan.io/address/0x9ff19a7d8e438b59f1f0f892caa004784f491e65) |
| JARDÍN Account (65 UserOps via Candide bundler) | [`0x0b0083c9…`](https://sepolia.etherscan.io/address/0x0b0083c930A5613E1391144edb132d8A75aa3DBb) |
| SPHINCs- C11 Verifier (shared) | [`0xC25ef566…`](https://sepolia.etherscan.io/address/0xC25ef566884DC36649c3618EEDF66d715427Fd74) |

**ethrex (EIP-8141 frame tx, pure PQ)** — balanced h=7, Q_MAX=128:

| Contract | Address |
|---|---|
| JARDÍN Frame Proxy (67-byte hand-optimised) | `0x627b9A657eac8c3463AD17009a424dFE3FDbd0b1` |
| JARDÍN Frame Impl | `0x5Ffe31E4676D3466268e28a75E51d1eFa4298620` |
| JARDÍN FORS+C Verifier | `0x4eaB29997D332A666c3C366217Ab177cF9A7C436` |
| SPHINCs- C11 Verifier | `0x3155755b79aA083bd953911C92705B7aA82a18F9` |

**On-chain validation (this release):**

- **ethrex frame**: 132/132 txs succeeded (1 register + 1 stateless + 128 compact + 1 re-register + 1 compact). Type 2 gas 120,552 – 120,708 — constant across `q = 1 … 128`.
- **Sepolia 4337 via Candide bundler**: final 20 txs (q=111…128 + re-register + q=1 in new slot) all succeeded, 100 % success rate. Type 1 `actualGasCost` 0.000566 ETH, Type 2 0.000385 ETH avg (tight ±0.1 % range across 18 compact sigs).

## Hardware Signer

Ledger Nano S+ app (ST33 Cortex-M0+, 48 MHz, no hardware keccak):
[`nconsigny/sphincs-ethereum-app` (branch `sphincs-c11`)](https://github.com/nconsigny/sphincs-ethereum-app/tree/sphincs-c11)

- **Compact signing: 3.1 s** (2,600 keccak for FORS+C + 32 counter grinds + USB overhead)
- Stateless C11 signing: 390 s (292 K keccak — rare, only for registration / emergency)
- NVRAM footprint per slot: ~4.3 KB (128 FORS+C pks + 127 Merkle internals + `r`, `q`, guards)

---

---

# JARDINERO — Plain-SPHINCS+ (SPX) Registration Variant

**JARDINERO** is the current production-oriented configuration of JARDÍN. Its
registration path is **plain SPHINCS+** (standard WOTS+ with checksum, not
WOTS+C) with the parameter set below. C11 is kept as an optional break-glass
recovery path, attached per account via `JardinAccount.attachC11Recovery()`
only when the user wants it.

Earlier drops of this branch used **T0** (`T0_W+C_h14_d7_a6_k39`, WOTS+C
hypertree) as the registration path. T0 is still available as
`JardinT0Verifier` if you want it, but the default account, factory and
frame-account now wire SPX instead.

## Why plain SPHINCS+

For a hardware wallet the two costs that matter are the *keygen* burned at
onboarding and the *sign hash count* paid on every registration. SPX has
`d=5, h'=4` ⇒ 16 top-layer WOTS keypairs (vs C11's 256), so onboarding is
cheap; and sign cost lands at ~36.6K keccak calls, well under C11's 292K.
Signatures are 6,512 B; verifier compute is 278K gas; on-chain cost on
Sepolia 4337 is dominated by the calldata floor (`64 × 6512 = 416.8K gas`),
so further micro-optimizing keccak counts has no effect on total fee.

## Parameters

| Name | Value | Purpose |
|---|---|---|
| scheme | plain SPHINCS+ | WOTS+ with checksum, FORS |
| n | 16 bytes | keccak256 truncated to 128 bits |
| h | 20 | total hypertree height |
| d | 5 | layers |
| h' | 4 | per-layer XMSS height → 16 WOTS keypairs/layer |
| a | 7 | FORS tree height (128 leaves / tree) |
| k | 20 | FORS trees |
| w | 8 | Winternitz, lg(w)=3 |
| l1 | 42 | message chains (⌊128/3⌋) |
| l2 | 3 | checksum chains (⌈log_w(l1·(w−1))⌉) |
| l | 45 | total WOTS chains |
| R | 32 bytes | per-signature randomness |
| ADRS | 12 bytes | compact (layer‖tree‖type‖kp‖chainAddr‖hashAddr, big-endian) |
| Hmsg | keccak256(R ‖ PKseed ‖ PKroot ‖ M) | full 256-bit, MSB-first parsing |
| q_s budget | 2^11 → 128 bits | security flat at 127.8 bits through 2^14 |

Signature layout (what the verifier receives):
```
[R (32)] [K=20 trees × (sk 16 + auth 7×16) = 2,560]
[D=5 layers × (WOTS 45×16 + XMSS auth 4×16) = 5×784 = 3,920]
= 6,512 bytes
```

## Signature Types (JardinAccount, ERC-4337)

| Type | Role | Payload |
|---|---|---|
| `0x01` | **ECDSA + SPX** (primary slot registration) | `[ecdsa 65][subSeed 16][subRoot 16][SPX sig 6,512]` = 6,609 B |
| `0x02` | ECDSA + FORS+C (compact, requires registered slot) | `[ecdsa 65][subSeed 16][subRoot 16][FORS+C sig]` = 2,598 B + 16·h |
| `0x03` | ECDSA + C11 (optional recovery — if attached) | `[ecdsa 65][C11 sig 3,976]` = 4,041 B |

At deploy time the account carries `spxPkSeed / spxPkRoot` and
`forscVerifier` (immutable). `c11Verifier` starts at `address(0)`; the user
attaches it later if desired. The slot-registration path never requires C11.

### Variable-height FORS+C

The FORS+C verifier accepts Type 2 sigs from slots with any outer Merkle
height `h ∈ [2, 8]` (Q_MAX = 2^h = 4 … 256). `h` is inferred from the
signature length with no extra wire byte:

```
h = (sig.length − 2453) / 16          (valid iff 2 ≤ h ≤ 8 and 16-aligned)
sig.length = 2452 (FORS+C body) + 1 (q) + 16·h (auth path)
```

`forscVerifier` is immutable on `JardinAccount`, so already-deployed accounts
(pre-variable-h) remain pinned to h=7. **New accounts created through the
variable-h factory (see "Deployed" below) can register slots at any
supported h.** This lets a hardware signer use a fast h=5 slot (Q_MAX=32)
for first-time onboarding and switch to h=7 later without swapping verifiers
or accounts.

## Measured Gas — 3×3 cycle on both chains

### Sepolia via Candide bundler

| | Actual gas used | `actualGasCost` avg |
|---|---|---|
| Type 1 (SPX + register) × 3 | ~floor-bound (calldata 416.8K) | **1.08 mETH** |
| Type 2 (FORS+C compact) × 3 | constant across q | **0.55 mETH** |

All 6/6 succeeded. SPX verify compute on-chain: **278K gas**;
`eth_estimateGas` on the deployed verifier: **401K**. EntryPoint + calldata
push the 4337 total above the pure-compute figure.

### ethrex (EIP-8141 frame)

| | Actual gas used |
|---|---|
| Type 1 (SPX + register) × 3 | **416K** avg (415,660) |
| Type 2 (FORS+C compact) × 3 | **121K** avg (120,672) |

All 6/6 succeeded with `F0=0x1 F1=0x1` (both frames OK). Frame savings vs
4337 are the EntryPoint overhead: no `handleOps` loop, no prefund dance, no
account ↔ EntryPoint bookkeeping.

## Deployed (JARDINERO — SPX)

**Sepolia (chain 11155111, EntryPoint v0.9)**

| Contract | Address |
|---|---|
| JARDÍN SPX Verifier | [`0xdC424A07…`](https://sepolia.etherscan.io/address/0xdC424A07981A5d6c8Afd0778141d3551e327b9AB) |
| FORS+C Verifier (variable h ∈ [2,8]) | [`0x99B10BB6…`](https://sepolia.etherscan.io/address/0x99B10BB66da9c538E4A4A7D6cBE4E56bFe2Be979) |
| JARDÍN Factory | [`0x08c0B125…`](https://sepolia.etherscan.io/address/0x08c0B1254a666dEB1c5A3972cC981EA6694c71c1) |
| JARDÍN Account (cycle sample) | [`0x88a61f94…`](https://sepolia.etherscan.io/address/0x88a61f94Ea5CaCaA0Cdd5FC39ece95A910fb10fe) |

Candide cycle (3× Type 1 SPX + 3× Type 2 FORS+C, 6/6 OK):
- Type 1: [`0x7f99f057…`](https://sepolia.etherscan.io/tx/0x7f99f057aa33df13976e818d757059051ee90fc34e87b6e46d3a8128ed4e7235) · [`0x4ca7825a…`](https://sepolia.etherscan.io/tx/0x4ca7825a32531a07cffa32a19fffb6246c5efebd94cc20fc0c2939ef4a9f51be) · [`0xda64ef93…`](https://sepolia.etherscan.io/tx/0xda64ef934673797f6842937d5eb5ebb9007fcaf2363d780fcb7063e6888a5edd)
- Type 2: [`0xb8b028be…`](https://sepolia.etherscan.io/tx/0xb8b028bed4f83ef7ee50ac51c2c5beefc66f854628f89812b0a6be643887e143) · [`0x72c0fea1…`](https://sepolia.etherscan.io/tx/0x72c0fea16e13af416de6f08260c2caf11a77868143902dc94ea8bfc0102fb99c) · [`0x904284dd…`](https://sepolia.etherscan.io/tx/0x904284dd6a5263139fa3c5dc6063b757550d4cd81780ab65ca63d3fd604028b2)

**ethrex (chain 1729, EIP-8141 frame tx)**

| Contract | Address |
|---|---|
| JARDÍN SPX Verifier | `0xF5b81Fe0B6F378f9E6A3fb6A6cD1921FCeA11799` |
| FORS+C Verifier | `0xa779C1D17bC5230c07afdC51376CAC1cb3Dd5314` |
| JardineroFrameAccount Impl | `0x67baFF31318638F497f4c4894Cd73918563942c8` |
| Frame Proxy (67-byte hand-optimised) | `0x6533158b042775e2FdFeF3cA1a782EFDbB8EB9b1` |

Frame cycle (3× Type 1 SPX + 3× Type 2 FORS+C, 6/6 OK):
- Type 1: `0x873d3930…9bd57cf`, `0x10d8e1d9…a7321f97`, `0x0a1c82f3…38b13f5b`
- Type 2: `0x4e5161c3…161a36a7`, `0x7b88852a…25e32f61`, `0xaa76bb2d…3dff4269`

**Legacy T0 deployment** (kept around; not the default path):

| Network | T0 Verifier | Factory (T0-based) | Frame Proxy (T0-based) |
|---|---|---|---|
| Sepolia | `0x188c4Ed4…AD5767` | `0xA9a71887…F9E95F0` | — |
| ethrex  | `0xFD6D23eE…7705e`  | —                      | `0xA3307BF3…47Db` |

## Usage

```bash
# Deploy full SPX stack to Sepolia
forge script script/DeployJardineroSepolia.s.sol --rpc-url sepolia --broadcast

# Run 4337 cycle (3× Type 1 SPX + 3× Type 2 FORS+C via Candide)
python3 script/jardin_spx_userop.py save-addresses <spxVerifier> <forscVerifier> <factory>
python3 script/jardin_spx_userop.py cycle

# Run frame-tx cycle on ethrex (requires an already-deployed proxy)
python3 script/jardinero_frame_tx.py cycle

# Re-deploy the frame proxy on ethrex (SPX in slot 0)
python3 script/deploy_jardin_frame.py \
  --impl <JardineroFrameAccount impl> \
  --verifier <SPX verifier> \
  --forsc <FORS+C verifier> \
  --seed <spxPkSeed as bytes32> --root <spxPkRoot as bytes32>
```

The legacy `jardin_t0_userop.py` and the `cycle-vh` mixed-h T0 flow are
still in-tree for reproducing older benchmarks but are not part of the
current default path.

---

## References

- [ePrint 2025/2203](https://eprint.iacr.org/2025/2203) — Kudinov & Nick, WOTS+C / FORS+C (SHRINCS, SHRIMPS)
- [SPHINCS-Parameters](https://github.com/nconsigny/SPHINCS-Parameters) — EVM-adapted parameter search with calibrated gas model
- [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) — Frame transactions (native account abstraction)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA / SPHINCS+ standard
- [Verity](https://github.com/Th0rgal/verity) — Lean 4 → EVM formally verified smart contracts
- [ZKnox/Kohaku](https://github.com/ethereum/kohaku) — PQ account pattern (shared verifier model)
- See [`writeUp.md`](./writeUp.md) for the full JARDÍN design and security analysis.
