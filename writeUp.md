# JARDÍN Design Decisions & Research Findings

## 1. Motivation: Why JARDÍN?

The stateless SPHINCs- variants (C6–C11) achieve post-quantum security on Ethereum, but at a cost: **4,008 bytes** per signature and **308K gas** per 4337 UserOp for C10. Every single transaction pays the full stateless price — WOTS+C chains, FORS+C trees, and a two-layer hypertree walk — even though most users sign only a few times per key.

JARDÍN asks: **what if normal operations used a cheaper few-time scheme, and the expensive stateless path was reserved for rare events?**

The answer is an unbalanced tree of FORS+C instances (the compact path) backed by a stateless SPHINCs- C11 fallback. The name — **Judicious Authentication from Random-subset Domain-separated Indexed Nodes** — reflects the core primitive: FORS (Forest of Random Subsets) with +C counter grinding and domain-separated tweakable hashing.

---

## 2. Scheme Selection: SHRINCS → SHRINCS-F → JARDÍN

The design draws from three ideas in the literature:

**SHRINCS** (Nick, 2025): Combines a stateful unbalanced XMSS tree of WOTS+C one-time signatures with a stateless SPHINCS+ fallback. First signature is ~308 bytes (WOTS+C at depth 1), growing by 16 bytes per use. The fallback is invoked when state is lost (e.g. seed restored on a new device). Problem: WOTS+C is **strictly one-time** — reusing a leaf is catastrophic (full key recovery).

**SHRINCS-F** (this design's predecessor): Replaces WOTS+C in the unbalanced tree with **FORS+C few-time signatures**. FORS+C tolerates accidental reuse: at r=2 (same leaf signed twice), security degrades gracefully from 128 bits to ~105 bits, rather than collapsing entirely. This makes the scheme resilient to state corruption, device rollbacks, and hardware faults.

**JARDÍN** (this implementation): Adds multi-device support via random slot IDs, hybrid ECDSA co-signing, and an ERC-4337/EIP-8141 dual account model. The key insight: each device generates an independent random `r`, derives its own FORS+C sub-key, and registers it on-chain via a single stateless C11 signature. Devices never coordinate.

---

## 3. FORS+C Parameter Selection

### Variant 1 (initial): k=16, a=8

The first implementation used k=16 FORS trees of height a=8 (256 leaves each):
- k×a = 128 bits of security at r=1
- Signature body: (k-1) × n × (1+a) + n = 15 × 16 × 9 + 16 = **2,212 bytes**
- Verify: ~43K gas (Foundry gasleft measurement), ~174K total 4337 gas
- Keygen per leaf: 16 trees × (256 secrets + 256 leaf hashes + 255 internal nodes) = **~12,273 keccak calls**
- Keygen for D=32 leaves: 32 × 12,273 = **~393K hashes** (~4 seconds in Python)

**Problem**: 393K hashes for keygen is too slow for constrained hardware (hardware wallets, mobile devices). The bottleneck is the 256 leaves per FORS tree (2^8 = 256).

### Variant 2 (final): k=26, a=5

Switching to k=26, a=5 trades more FORS trees for shallower trees:
- k×a = 130 bits of security at r=1 (slightly better than variant 1)
- Signature body: 25 × 16 × 6 + 16 = **2,452 bytes** (+240 bytes vs variant 1)
- Verify: ~49K gas (Foundry), ~174K total 4337 gas
- Keygen per leaf: 26 trees × (32 secrets + 32 leaf hashes + 31 internal nodes) = **~2,470 keccak calls**
- Keygen for D=32 leaves: 32 × 2,470 = **~79K hashes** (~1 second in Python)

**5x faster keygen** at the cost of 240 extra signature bytes. The verify gas is nearly identical because the total operation count is similar: 25 × 6 = 150 ops (variant 2) vs 15 × 9 = 135 ops (variant 1), and calldata cost differences roughly cancel out.

### Why not k=22, a=6 (variant 1 from the table)?

Variant 1 (k=22, a=6) gives slightly smaller signatures (2,420 B) but keygen is 4K hashes per leaf — double variant 2. For D=32, that's 134K hashes vs 79K. The 48-byte signature saving doesn't justify the keygen cost on constrained devices.

### Security comparison at r=2 (accidental double-signing)

| Variant | k | a | k×a | r=1 | r=2 | r=3 |
|---------|---|---|-----|-----|-----|-----|
| 1 (k=22, a=6) | 22 | 6 | 132 | 128 | 110 | 98 |
| **2 (k=26, a=5)** | **26** | **5** | **130** | **128** | **105** | **90** |
| Original (k=16, a=8) | 16 | 8 | 128 | 128 | 112 | 103 |

Variant 2 has slightly lower r=2 security (105 vs 112 bits) due to fewer leaves per tree (32 vs 256). This is acceptable: 105 bits still requires ~2^105 work to forge.

---

## 4. The Unbalanced Merkle Tree

### Structure

The unbalanced tree commits Q_MAX FORS+C public keys under a single root (subPkRoot). Each leaf is at a unique depth, so the auth path length encodes the leaf index:

```
              root (depth 0)
             /    \
          spine[0]  PK[0]       q=1, auth=1 node (16 B)
           /    \
        spine[1]  PK[1]         q=2, auth=2 nodes (32 B)
          ...
        spine[D-2]  PK[D-2]     q=D-1, auth=D-1 nodes
          /    \
       sentinel  PK[D-1]        q=D, auth=D nodes
```

The sentinel is a deterministic hash: `keccak256(seed || sk_seed || "jardin_sentinel")`. It ensures every q has a unique auth path length, allowing the verifier to derive q from `(sig.length - FORSC_BODY) / 16` without an explicit field.

### Internal hash count

The tree requires D internal th_pair hashes (D-1 spine nodes + 1 root), plus 1 sentinel computation. For D=32: **33 hashes** — negligible compared to the ~79K FORS keygen hashes.

### Why not remove the sentinel?

We explored removing the sentinel to save 1 hash and 16 bytes on the last signature. Without it, the bottom two leaves (q=D-1 and q=D) share the same depth, producing auth paths of equal length. The verifier can no longer derive q from the signature.

This matters because q is used in the FORS address domain separation: `make_adrs(0, 0, FORS_TREE, tree_idx, q, height, node_idx)`. Without knowing q, the verifier can't compute the correct tweakable hash addresses.

Options considered:
1. **Add q as an explicit byte** — +1 byte per signature, but changes the signature layout
2. **Remove q from FORS addresses** — weaker domain separation (still secure, but less clean)
3. **Keep the sentinel** — 1 extra hash in keygen, 16 extra bytes on the very last signature only

We kept the sentinel. The cost is negligible (1/79,000 of keygen, 16/2,468 of the last sig only), and it preserves the clean property that q is always self-evident from the signature.

---

## 5. The Random Slot `r`

### Design

Each FORS+C sub-key is bound to a random 32-byte slot ID `r`:
- `r = hardware_rng(32)` — generated on the device, 2^256 collision space
- `sub_sk_seed = HMAC-SHA512(masterSkSeed, r)` — deterministic sub-key derivation
- On-chain: `slots[keccak256(r)] = keccak256(subPkSeed, subPkRoot)`

The contract stores `H(r)`, not `r` itself. The raw `r` is revealed once during Type 1 registration and never reused. This design enables:

1. **Multi-device independence**: Device A uses `r_A`, Device B uses `r_B`. Both register independently via Type 1. Their FORS+C trees are completely separate — no coordination needed.

2. **Stateless backup**: The 24-word seed recovers the master key. A restored device generates a fresh `r_C`, registers a new slot, and starts signing. The old slot `H(r_A)` is orphaned but harmless.

3. **Emergency fallback**: Setting `r = 0x00..0` in Type 1 skips registration entirely. The C11 signature authenticates the action without creating a slot.

### Why not derive `r` from the seed?

If `r` were deterministic from the seed (e.g. `r = HMAC(masterSkSeed, device_index)`), two devices restoring from the same seed would generate the same `r` and the same FORS+C sub-key. They'd both sign at the same q values, degrading FORS+C security (r=2, then r=3, etc.). Random `r` from hardware RNG avoids this entirely — collision probability is 2^-256.

---

## 6. On-Chain Leaf Counter: Why We Removed It

### The three options from the spec

**Option A** — EntryPoint nonce key: Use `H(r)` truncated to 192 bits as the ERC-4337 nonce key. The EntryPoint auto-tracks the sequence. Zero storage cost, but only works in 4337 (not Frame transactions).

**Option B** — Contract storage: `mapping(bytes32 => uint32) public nextLeaf`. Updated on each Type 2 verification. Costs ~5K gas per sig (warm SSTORE). Works everywhere.

**Option C** — Signature-embedded: q is derived from the auth path length. The contract doesn't track state; it just verifies whatever the signer provides.

### Why we chose Option C (no counter)

The counter doesn't add security — it's a convenience wrapper. The argument:

1. **The counter prevents double-signing the same leaf q.** But the state corruption that causes double-signing happens **off-chain**. If the signer's device rolls back to a state before it queried the counter, it would still sign with the wrong q. The counter only helps if the signer actively queries it — which it could also do by reading past transaction history.

2. **FORS+C tolerates double-signing by design.** At r=2 (same leaf used twice), security degrades to 105 bits. At r=3, to 90 bits. This graceful degradation is the entire point of choosing FORS+C over WOTS+C. A counter would be defense-in-depth against a threat the scheme is already designed to handle.

3. **Protocol-level replay protection exists.** The EntryPoint nonce (4337) or Frame nonce prevents the same signature from being submitted twice. The only risk is the signer **creating two different signatures** for the same q — which is an off-chain state management problem, not an on-chain enforcement problem.

4. **The counter costs 5K gas per signature.** For a scheme optimized to save ~150K gas per tx over the stateless path, spending 5K on a counter that doesn't add security is a meaningful fraction of the savings.

We stripped the counter. The contract is fully stateless for Type 2 verification. The signer tracks q locally and can recover it from on-chain transaction history if needed.

---

## 7. C10 → C11: Hardware Wallet Compatibility

### The problem with C10

C10 (h=18, d=2, subtree_h=9) requires 609K keccak calls to sign. On a hardware wallet computing ~10K keccak/s, that's ~60 seconds per Type 1 signature. Unusable.

### Why C11

C11 (h=16, d=2, subtree_h=8) requires only 292K keccak calls — **2x faster than C10**. The tradeoff:

| | C10 | C11 |
|---|---|---|
| Signing cost | 609K hashes | **292K hashes** |
| Sig size | 4,008 B | **3,976 B** (32 B smaller) |
| Verify gas | 115K | **116K** (~same) |
| Security at 2^14 sigs | 128 bits | **128 bits** |
| Security at 2^16 sigs | 128 bits | **118 bits** |
| Security at 2^20 sigs | 104 bits | **86 bits** |

The security reduction at high signature counts doesn't matter for JARDÍN: C11 is only used for Type 1 (registration + emergency), not for every transaction. With Q_MAX=32, a user needs 1 C11 signature per 32 compact transactions. Even a very active wallet producing 10,000 compact sigs would only need ~312 C11 signatures — well within the 2^14 safe zone (128-bit security).

---

## 8. Hybrid ECDSA: Belt-and-Suspenders

### The design choice

Every JardinAccount UserOp requires **both** an ECDSA signature and a post-quantum signature. Neither alone is sufficient.

The signature layout prepends a 65-byte ECDSA signature after the type byte:
```
[type 1B][ecdsaSig 65B][...PQ payload...]
```

The account validates ECDSA first (3K gas, `ecrecover`), then the PQ signature (C11 or FORS+C). If either fails, the UserOp is rejected.

### Why hybrid?

1. **Transition safety**: Until quantum computers actually break ECDSA, the hybrid scheme is as secure as the stronger of the two. If FORS+C has a subtle implementation bug, ECDSA still protects. If Shor's algorithm breaks secp256k1, the hash-based signature still protects.

2. **Negligible cost**: ECDSA verification costs ~3K gas. Against a 174K Type 2 total, that's 1.7% overhead.

3. **Key separation**: ECDSA derives from BIP-32 (m/44'/60'/0'/0/0), SPHINCs- derives from HMAC-SHA512. Independent paths — compromising one doesn't leak the other.

### The frame account exception

JardinFrameAccount is **pure PQ** — no ECDSA. This is intentional: frame transactions target a post-quantum future where ECDSA may be broken. The frame account saves 65 bytes per signature and ~3K gas per verification.

---

## 9. Frame vs 4337: Two Account Models

### ERC-4337 (JardinAccount)

- Hybrid ECDSA + PQ on every UserOp
- Goes through EntryPoint.handleOps → account._validateSignature
- EntryPoint nonce provides replay protection
- Higher gas due to EntryPoint overhead (~50K) and ECDSA (~3K)
- Works on any EVM chain with the EntryPoint deployed

### EIP-8141 Frame (JardinFrameAccount)

- Pure PQ, no ECDSA
- Direct call to verifyAndApprove(sigHash, sig, scope)
- Frame protocol nonce provides replay protection
- Lower gas: no EntryPoint overhead, no ECDSA
- Only works on frame-enabled chains (ethrex)

### Measured comparison (Sepolia)

| | Frame (pure PQ) | 4337 (hybrid) | Savings |
|---|---|---|---|
| Type 1 (register) | **235K** | 323K | 27% |
| Type 2 (compact q=1) | **125K** | 174K | 28% |
| Type 1 sig | 4,041 B | 4,138 B | 97 B |
| Type 2 sig | 2,533 B | 2,598 B | 65 B |

Both models share the same verifiers (C11 and FORS+C) and the same slot mechanism. The difference is purely in the account wrapper.

---

## 10. H_msg: 192-Byte Domain-Separated Hash

### Why 192 bytes instead of 160?

The existing SPHINCs- verifiers use a 160-byte H_msg:
```
keccak256(seed || root || R || message || domain_mask) = 5 × 32 = 160 bytes
```

JARDÍN's FORS+C verifier adds a **counter** field for grinding:
```
keccak256(seed || root || R || message || counter || domain_mask) = 6 × 32 = 192 bytes
```

The counter enables the signer to iterate until the last FORS index is zero (forced-zero grinding) without re-sampling R. This is more efficient than the alternative (re-deriving R via PRF for each attempt), which would require an additional hash call per trial.

### Forced-zero condition

For k=26, a=5: the last 5 bits of the FORS index range (bits 125-129 of the digest) must be zero. The signer iterates the counter until this condition is met. Expected trials: 2^5 = 32. Cost: 32 hash evaluations — negligible.

The forced-zero trick (from FORS+C / SPHINCS+C) eliminates one tree from the signature: instead of 26 tree auth paths, only 25 are needed. The 26th tree's root is included directly (16 bytes), saving 25 × 5 × 16 - 16 = 1,984 bytes. The signature would be 4,436 bytes without +C; it's 2,452 bytes with +C.

---

## 11. Address Scheme: Domain Separation via Tweakable Hashing

### FORS tree addresses

Every hash in JARDÍN uses a tweakable hash function: `th(seed, adrs, input)` or `th_pair(seed, adrs, left, right)`, where `adrs` is a 256-bit address encoding the operation context.

For FORS trees: `adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, q, height, node_idx)`

The `q` field (unbalanced tree leaf index) appears in the `ci` (chain index) position. This ensures that FORS trees for different q values use different addresses, even though they share the same seed. Without this, an attacker observing signatures at q=3 and q=7 could potentially mix-and-match FORS openings across leaves.

### Unbalanced tree addresses

For the unbalanced tree walk: `adrs = make_adrs(0, 0, ADRS_UNBALANCED, 0, 0, depth, 0)`

The `depth` field is the absolute depth from the root (0 = root, 1 = first spine node, etc.). This is consistent between keygen (building top-down) and verification (walking bottom-up). The verifier computes `depth = q - 1 - j` for step j, which matches the keygen's depth assignment.

### FORS root compression addresses

For the final compression of 26 tree roots into one FORS public key:
`adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0)`

Again, `q` is included for domain separation between different unbalanced tree leaves.

---

## 12. Gas Analysis: Where the Gas Goes

### Type 2 (FORS+C compact, q=1) — 174K total 4337 gas

| Component | Gas | Notes |
|-----------|-----|-------|
| EntryPoint overhead | ~50K | handleOps, nonce check, accounting |
| Calldata (2,598 bytes) | ~42K | ~16 gas per non-zero byte |
| ECDSA ecrecover | ~3K | |
| Slot lookup (SLOAD) | ~2.1K | Warm after first access |
| keccak slot check | ~0.1K | H(subSeed, subRoot) == slots[key] |
| FORS+C verify (25 trees) | ~49K | 25 × (leaf hash + 5 auth levels) |
| Root compression (26 roots) | ~1K | Single keccak of 896 bytes |
| Unbalanced tree walk (1 node) | ~0.5K | 1 × th_pair |
| Account wrapper overhead | ~26K | ABI decode, staticcall, return |

### Gas growth per q

Each additional q adds:
- 16 bytes of calldata: ~256 gas
- 1 unbalanced tree th_pair: ~250 gas
- **Total: ~498 gas per q** (measured average across 32 leaves)

At q=32: 174K + 31 × 498 = **189K** — confirmed by on-chain measurement.

---

## 13. Full Cycle: 36 Transactions on Sepolia

We executed a complete slot lifecycle on Sepolia, demonstrating the full JARDÍN flow:

1. **Deploy** JardinAccount via CREATE2 factory
2. **Type 1** — Register slot 1 (ECDSA + C11 + sub-key registration)
3. **Type 2 × 32** — Compact FORS+C signatures from q=1 to q=32
4. **Type 1** — Re-register slot 2 (fresh sub-key, new `r`)
5. **Type 2 × 2** — Compact signatures on the new slot (q=1, q=2)

All 36 transactions succeeded. The re-registration confirmed that:
- The new slot uses a completely independent FORS+C tree
- q resets to 1 on the new slot
- Gas returns to the q=1 baseline (174K)

Account address: [`0x05B3aad92B34BDD207F4305FC6100318F041F583`](https://sepolia.etherscan.io/address/0x05B3aad92B34BDD207F4305FC6100318F041F583)

### JardinFrameAccount (pure PQ)

Additionally tested the frame account model on Sepolia (verification logic only — the APPROVE opcode is a no-op on standard EVM):

| Type | Gas | Tx |
|------|-----|----| 
| Type 1 (C11 + register) | **235K** | [`0x371ca6e7...`](https://sepolia.etherscan.io/tx/0x371ca6e7114c2f9feba291fafeaf337b40e1f5293924bb48ed6c36428fae95f8) |
| Type 2 (FORS+C q=1) | **125K** | [`0xa7900072...`](https://sepolia.etherscan.io/tx/0xa7900072a111aa61cfcf886e88b351686fdb8e24eb379f922617d354fda95469) |

Frame account: [`0x5cc7d476...`](https://sepolia.etherscan.io/address/0x5cc7d476d9b7e08f52cae9caa6d32df100b5b650)

---

## 14. Open Questions & Future Work

1. **Rust/WASM signer for JARDÍN**: The current signer is Python (~1s keygen for D=32). A Rust WASM implementation would bring this to ~50ms, enabling browser wallets.

2. **BIP-39 integration**: The current key derivation uses a placeholder path. Production would use `HMAC-SHA512("sphincs-c11-v1", bip39_seed)` with proper BIP-44 separation, matching the existing Rust signer pattern.

3. **ethrex frame deployment**: The JardinFrameAccount has been tested on Sepolia (verification logic only). Full deployment on ethrex with the APPROVE opcode would demonstrate the pure PQ path end-to-end.

4. **Formal verification**: The existing Verity kernel proves Merkle acceptance for the SPHINCs- verifier. Extending this to cover the FORS+C-only verification and unbalanced tree walk would provide machine-checked guarantees for the JARDÍN compact path.

5. **Multi-sig / threshold**: The JARDÍN slot mechanism is per-device. A multi-sig variant would require k-of-n slot agreement, potentially using the multi-OTS construction from the Blockstream report.

6. **Sentinel removal**: With an explicit 1-byte q field in the signature, the sentinel could be removed, saving 1 hash in keygen and 16 bytes on the last signature. This is a minor optimization that trades signature format simplicity for marginal space savings.
