# JARDIN: Judicious Authentication from Randomized Domain-separated Indexed Nodes

_This post builds on_ [_SPHINCs-: Efficient Stateless Post-Quantum Signature Verification on the EVM_](https://docs.fileverse.io/0x23e01d1f0c0bc7247ad18631f0d6d7ef78a3af82/28#key=kdkUKVWbzUtAOOe0NrHdJAgVEmarQ0cVlPAnypIInTOYnEleY9H0jX-3Bn98t1z5)_, which describes the underlying stateless signature scheme and its parameter space._

* * *


## Abstract

Most Ethereum accounts are secured by ECDSA, a signature scheme that will be broken by a sufficiently large quantum computer running Shor's algorithm. Recent resource estimates by Babbush et al. [1] suggest this threat may materialise sooner than previously assumed, creating an urgent need for post-quantum signature verification at the execution layer. Among the candidate families, hash-based signatures stand out for their conceptual simplicity and conservative security foundations: their security reduces entirely to the properties of hash functions, primitives that are well-understood and battle-tested, making them easy to reason about.

[SPHINCs-](https://github.com/nconsigny/SPHINCs-) [2] adapts the NIST-standardised SLH-DSA scheme for the EVM, achieving the lowest known on-chain verification cost for PQ hash-based signatures. But stateless signing remains expensive: 4.3M keccak calls for C7, 292K for C11, reaching 390 seconds on constrained hardware wallets. Kudinov and Nick [3] proposed innovative hybrid designs (SHRINCS [4], SHRIMPS [5]) combining compact stateful signatures with a stateless SPHINCS+ fallback, but their compact path uses WOTS+C one-time signatures, which break catastrophically on reuse. A signature scheme that places catastrophic failure on the fault-resistance of a monotonic counter changes the security model of the signer in ways that are difficult to audit, particularly given that state rollback through fault injection remains a practical threat on secure elements [6].

We present [JARDIN](https://github.com/nconsigny/SPHINCs-?tab=readme-ov-file#jard%C3%ADn--compact--stateless-hybrid-account) (Judicious Authentication from Random-subset Domain-separated Indexed Nodes), a two-tier architecture that combines SPHINCs-'s cheap EVM verification with a SHRINCS-style compact/stateless split, replacing WOTS+C with FORS+C few-time signatures in the compact path. FORS+C degrades under accidental reuse (degradation can be adapted to the signing budget), removing the critical dependency on perfect state management. The compact path uses a balanced Merkle tree of 128 FORS+C instances (k=26, a=5, 130-bit one-time security, h=7) with a stateless SPHINCs- C11 fallback. We leverage the persistent memory of the smart accounts by registering the compact path as slots in the memory with a SPHINCS- stateless signature. When deriving the compact path from the seed we add randomness `r` to each lane then we commit a slot with mapping `slots[H(subPkSeed, subPkRoot)] = 1`. Once the JARDIN lane is registered normal transactions use the compact path at 119K gas and 2.6 KB; device registration and emergency recovery use the stateless path at 235K gas and 4.1 KB. The leaf index q is encoded as a single byte in the signature, requiring no on-chain state. JARDIN supports unlimited independent devices from a single 24-word mnemonic with no inter-device coordination, and enforces anti-rollback leaf consumption via hardware burn-before-sign. We implement and measure the scheme on a constrained secure element hardware wallet (3-second compact signing versus 390 seconds for the full stateless path).

* * *

## 1. The Problem JARDIN Solves

The companion post on SPHINCs- described how to get post-quantum verification down to 127K gas. But verification is only half the problem. The signer must also be practical.

SPHINCs- C7 requires 4.3M keccak256 calls to sign. On a desktop at ~1M hashes/second, that is ~4 seconds, acceptable. On a constrained secure element (eg. the Ledger nano S+ with a ST33 Cortex-M0+, 48MHz, no hardware keccak), signing would take minutes. Even C11, the fastest variant at 292K hashes, takes 390 seconds (6.5 minutes).

Linear interpolation from Ledger's SPHINCS+-128s benchmark (6 minutes 18 seconds for 2.0M hashes) puts C7 at 11~13 minutes and C11 at ~6.5 minutes on a comparable secure element. Our measured C11 time (390 seconds) is consistent with this estimate.

JARDIN's contribution is showing that one does not need to run the full stateless scheme on every transaction. A JARDIN can be signed on constrained hardware in 3 seconds, and cost 48K gas to verify (full frame tx at 119K gas).

## 2. From one time to few time signatures

The idea of combining a compact stateful path with a stateless fallback comes from Kudinov and Nick [3], who proposed SHRINCS [4] and SHRIMPS [5] as part of their work on hash-based signatures for Bitcoin. SHRINCS builds a stateful tree of WOTS+C one-time signatures. When the tree is exhausted or state is lost, the scheme falls back to a full stateless SPHINCS+ signature.

A WOTS+ signature reveals hash chain values at specific positions. If the same WOTS+ leaf signs two different messages, the attacker obtains chain values at two different positions per chain. For 43 chains, that is 43 pairs of revealed positions. The "slack" in the encoding space (valid message encodings whose digit positions all fall within the revealed ranges) can be enormous, potentially 2^40 or more forgeable messages.

For a hardware wallet, state corruption is not hypothetical. Firmware updates, crashes during signing, power loss, device rollbacks, and flash memory faults are expected over the device lifetime. For a software signer it's even easier to imagine attacks that would confuse the state management. A scheme where any state glitch is catastrophic is hard to deploy.

## 3. FORS+C in the Compact Path

The idea is straightforward, JARDIN replaces WOTS+C with FORS+C in the compact path. Each leaf of the Merkle tree is a FORS+C instance rather than a WOTS+C instance.

### 3.1 Why FORS tolerates reuse

A FORS signature reveals k secret leaf values, one from each of k independent binary trees of height a (2^a leaves each). To forge a FORS signature, the attacker needs a message whose k required leaf indices all fall within the set of previously revealed leaves.

After γ previous signatures on the same FORS+C instance, the first k_open = 25 trees each have at most γ revealed leaves out of 2^a. The removed tree always opens leaf 0, contributing a fixed factor of 2^{-a'}. The forgery probability is:

```
p_γ       = 1 - (1 - 1/2^a)^γ
P_forge   = p_γ^(k_open) * 2^(-a')
security  = -log2(P_forge)
```

Using the standard generic-attack heuristic for FORS-style reuse, the conditional forgery probability for a reused compact-path instance is: P<sub>forge∣γ,q​</sub>≈p<sub>γ</sub><sup>25</sup>​⋅2<sup>−5</sup>
This degrades gradually:

| Reuses (y) | Security for (k=26, a=5) | Security for (k=16, a=8) |
| ---------- | ------------------------ | ------------------------ |
| 1          | 130-bit                  | 128-bit                  |
| 2          | 105-bit                  | 112-bit                  |
| 3          | 91-bit                   | 103-bit                  |
| 5          | 74-bit                   | 91-bit                   |

At r=2 (one accidental double-sign), the attacker still needs 2^105 work to forge with our parameters. Compare WOTS+C, where r=2 potentially enables complete key recovery.

### 3.2 Why FORS signatures are larger

WOTS+ chain values need no Merkle proof: the hash chain itself is the proof (the verifier hashes forward to the public value). FORS tree leaves require Merkle auth paths: a * n bytes per tree. With k*a >= 128 for 128-bit security, the minimum FORS+C signature body is approximately k*a*n = 2,048 bytes at n=16.

This is the fundamental size floor. JARDIN's compact path signatures (2,598 B constant) are larger than SHRINCS's (~308 B at q=1), but the graceful degradation under reuse is worth the cost.

### 3.3 Algorithms: from forest (FORS) to JARDIN

This section describes how JARDIN adapts the standard FORS algorithms from SLH-DSA (FIPS 205 [7], Section 8) and adds two new layers: the FORS+C forced-zero optimisation from Kudinov and Nick [3], and the balanced Merkle tree.

**Standard FORS** (FIPS 205 [7], Algorithms 14 to 17). A FORS instance consists of k independent Merkle trees, each of height a with t = 2^a leaves. Each leaf is the hash of a pseudorandom secret value derived from SK.seed via `fors_skGen` (FIPS 205, Algorithm 14), which calls PRF with a `FORS_PRF`-typed address encoding the leaf's position. The `fors_node` function (FIPS 205, Algorithm 15) recursively builds Merkle subtrees: leaf nodes hash the secret via F(PK.seed, ADRS, sk), and internal nodes hash their two children via H(PK.seed, ADRS, lnode || rnode).

Signing with `fors_sign` (FIPS 205 Algorithm 16) splits the k*a-bit message digest `md` into k chunks of a bits via `base_2b(md, a, k)`, producing k leaf indices. For each tree i, the signature includes the secret value at position i * 2^a + indices[i] and the a-node authentication path from that leaf to the tree root.

Verification (`fors_pkFromSig`, Algorithm 17) reconstructs each tree root from the revealed secret and auth path, walking bottom-up through the Merkle tree. The k reconstructed roots are compressed into a single FORS public key via T_k(PK.seed, forspkADRS, roots). This is analogous to `ecrecover` in ECDSA: the verifier does not receive the public key directly but reconstructs it from the signature and checks it against a stored commitment. In JARDIN, the contract stores `keccak256(subPkSeed, subPkRoot)` and the verifier reconstructs subPkRoot via this same process.

**FORS+C (Kudinov and Nick [3]).** The +C optimisation forces the last tree's leaf index to zero by grinding a 4-byte counter in the message hash. JARDIN derives a dedicated randomiser secret during slot creation:

```
slot_sk_seed = HMAC-SHA512(masterSkSeed, "JARDIN/SKSEED" || r)[0:32]
slot_sk_prf  = HMAC-SHA512(masterSkSeed, "JARDIN/SKPRF"  || r)[0:16]
```

The compact digest is then:

```
M*     = "JARDIN/TYPE2/v1" || subPkSeed || subPkRoot || q || message
R      = PRF_msg(slot_sk_prf, opt_rand, uint32_be(counter) || M*)
digest = H_msg(R, subPkSeed, subPkRoot, uint32_be(counter) || M*)
```

where PRF_msg and H_msg are instantiated as keccak256 with domain-separated inputs, and opt_rand = subPkSeed for deterministic signing.

The signer iterates counter until the last a bits of the digest are zero: (digest >> (k_open)*a) & (2^a - 1) == 0.

For k_open=25, a=5, this means the last 5 bits of the 130-bit digest must be zero. Expected trials: 2^a = 32. Both R (16 bytes) and counter (4 bytes) are included in the signature so the verifier can recompute the exact digest.

Since the last tree always opens leaf 0, its auth path is omitted entirely. The signature opens only the first k_open = 25 trees.

```
k_total = 26
k_open  = 25
a = a'  = 5
digest bits = idx_0 || ... || idx_24 || zero_5
SIG_FORSC   = counter:4 || Π_{i=0}^{24}( sk_i:16 || auth_i:80 )
```

**JARDIN address scheme.** FIPS 205 uses a 32-byte ADRS with 12 bytes for the tree address. JARDIN compresses the tree address to 8 bytes, freeing 4 bytes for a new ci field that carries the FORS+C leaf index q. The FIPS-assigned type values FORS_TREE = 3, FORS_ROOTS = 4, FORS_PRF = 6 are kept unchanged. The balanced Merkle tree uses JARDIN_MERKLE = 16, outside the FIPS range. For compact-path FORS+C, kp is fixed to 0 and the ci field carries q. The treeIndex field y remains continuous across all FORS trees exactly as in FIPS 205 (Algorithms 14 to 17).

```
ADRS (32 bytes) = layer:4 || tree:8 || type:4 || kp:4 || ci:4 || x:4 || y:4
type = 3 FORS_TREE
kp=0 ci=q x=treeHeight y=treeIndex (continuous across all k trees)
type = 4 FORS_ROOTS
kp=0 ci=q x=0 y=0
type = 6 FORS_PRF
kp=0 ci=q x=0 y=treeIndex (same leaf index as FORS_TREE)
type = 16 JARDIN_MERKLE
kp=0 ci=0 x=level y=nodeIndex
```

The ci=q field provides domain separation between FORS+C instances at different balanced-tree leaf positions: two signatures at q=3 and q=7 use different tweakable-hash addresses even though they share the same seed. The ci field is only needed for FORS types (3, 4, 6) — the Merkle tree type (16) uses (level, nodeIndex) for full domain separation of internal nodes, so ci is set to 0.

**Hash function instantiation.** FIPS 205 defines six abstract functions (PRF_msg, H_msg, PRF, T_k, H, F) instantiated with SHAKE256 or SHA2. JARDIN, like SPHINCS-, replaces all with keccak256:

* F(PK.seed, ADRS, M) becomes `th(seed, adrs, input) = keccak256(seed || adrs || input) & N_MASK`
* H(PK.seed, ADRS, M) becomes `th_pair(seed, adrs, left, right) = keccak256(seed || adrs || left || right) & N_MASK`
* T_k(PK.seed, ADRS, roots) becomes `th_multi(seed, adrs, vals) = keccak256(seed || adrs || vals[0] || ... || vals[k-1]) & N_MASK`

where N_MASK truncates to n=16 bytes (128 bits). The on-chain verifier implements these directly in Yul assembly, using the EVM `KECCAK256` opcode.

**Balanced Merkle tree (JARDIN-specific).** This structure is not present in FIPS 205. It commits Q_MAX = 2^h = 128 independent FORS+C public keys under a single root using a standard balanced binary Merkle tree of height h=7.

Keygen builds the tree bottom-up:

```
-- Compute all FORS+C leaf public keys (q is 1-indexed for ADRS ci field)
For q = 1 to Q_MAX:
  leaves[q-1] = compute_forsc_pk(seed, sk_seed, q)

-- Build balanced tree bottom-up
-- Level h (=7) = leaves, level 0 = root
nodes[h] = leaves
For level = h-1 down to 0:
  For i = 0 to 2^level - 1:
    nodes[level][i] = th_pair(seed,
      ADRS(type=16, ci=0, x=level, y=i),
      nodes[level+1][2*i],
      nodes[level+1][2*i+1])

root = nodes[0][0]
```

The auth path for leaf q (0-indexed) consists of h=7 sibling nodes, one per level:

```
For j = 0 to h-1:
  auth[j] = sibling of the node on q's path at level h-1-j
Total: h = 7 nodes, each n=16 bytes, always 112 bytes
```

Verification walks the auth path bottom-up, reconstructing the root:

```
forsPk = verify_forsc(sig)             -- FORS+C verification (uses ci=q in FORS ADRS)
node = forsPk
For j = 0 to h-1:
  level = h - 1 - j
  parentIndex = q >> (j + 1)
  if bit j of q is 0:
    node = th_pair(seed, ADRS(type=16, ci=0, x=level, y=parentIndex), node, auth[j])
  else:
    node = th_pair(seed, ADRS(type=16, ci=0, x=level, y=parentIndex), auth[j], node)
Check: node == pkRoot
```

This is a standard Merkle inclusion proof. The bits of q determine left/right ordering at each level. The ADRS encodes (level, parentIndex) for full domain separation of every internal hash.

## 4. Architecture

### 4.1 Two signature types

**Type 1: Stateless C11 master signature + optional sub-key registration.**

```
[0x01][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][C11 sig ~3,944B]

Total: ~4,106 bytes | 235K gas (frame)| 390 seconds on secure element
```

Used for: first transaction per device (registers the device's sub-key), emergency recovery, and slot exhaustion re-registration. Setting subPkSeed=0 and subPkRoot=0 skips registration for stateless fallback.

**Type 2: FORS+C compact via registered sub-key.**

```
[0x02][ecdsaSig 65B][subPkSeed 16B][subPkRoot 16B][q 1B][FORS+C sig][merkleAuth 112B]
Total: ~2,598 bytes (frame, constant) | 119K gas (frame) | 3.1 seconds on secure element
```

The verifier reads q from the explicit 1-byte field, recomputes the digest from R, counter, subPkSeed, subPkRoot, q, and the message, checks that the last a bits are zero, verifies the FORS+C body, then walks the balanced Merkle auth path (h=7 nodes) up to subPkRoot. The contract verifies `slots[keccak256(subPkSeed, subPkRoot)] != 0`, then verifies the FORS+C signature under the sub-key.

### 4.2 The balanced Merkle tree

JARDIN commits Q_MAX = 128 independent FORS+C public keys under a single root using a balanced binary Merkle tree of height h=7. The auth path for any leaf q consists of exactly h=7 sibling nodes (112 bytes), regardless of q.

All compact-path signatures have constant size, constant verification gas, and constant calldata cost. Since JARDIN wallets are expected to consume most of their slot budget (unlike Bitcoin wallets where average q is 1-2 [4]), the balanced tree provides better average-case performance and a simpler verifier than a spine-shaped alternative.

## 5. FORS+C Parameter Selection

### 5.1 Chosen parameters: k=26, a=5, h=7

| Parameter | Value              | Rationale                                   |
| --------- | ------------------ | ------------------------------------------- |
| k         | 26                 | k*a = 130 >= 128 for one-time security      |
| a         | 5 (32 leaves/tree) | Minimises signing cost: ~2,600 hashes       |
| n         | 16 bytes           | 128-bit hash output                         |
| Q_MAX     | 128 (h=7)          | Balanced tree height chosen for keygen budget (~5 min on SE) |

Signing cost: 26 trees * ~100 hashes = 2,600 keccak calls. Keygen cost per leaf: 26 * (32 + 32 + 31) + 1 = 2,471 hashes. For 128 leaves: 128 * 2,471 + 127 = 316,415 hashes (~301 seconds on a secure element). This is a one-time cost per slot.

### 5.2 The r=2 security trade-off

k=26, a=5 gives 105-bit security under double-signing (r=2). 2^105 hash evaluations at 10^12 hashes/second would take 10^13 years. The 3-second signing time enables the scheme on constrained hardware.

## 6. Multi-Device Architecture

Each device generates an independent 32-byte random `r` from its hardware RNG:

```
r = hardware_rng(32)                             -- 2^256 space
sub_sk_seed = HMAC-SHA512(masterSkSeed, r)       -- deterministic from master + r
sub_pk_seed, sub_pk_root = FORS+C_keygen(sub_sk_seed)    -- balanced tree of 128 keys
```

The value `r` never leaves the device. The contract identifies sub-keys by their public components: registration writes `slots[keccak256(subPkSeed, subPkRoot)] = 1` and verification checks that this slot is nonzero. Since `subPkSeed` and `subPkRoot` are already present in every Type 2 signature for FORS+C verification, no additional bytes are needed for slot lookup.

Because `r` is sampled from a 256-bit random source, two independent devices restoring from the same 24-word mnemonic derive independent sub-keys (collision probability 2^{-256}), enabling unlimited devices without inter-device coordination.

## 7. Leaf Index Encoding

The leaf index q is encoded as a single byte in the Type 2 signature. The verifier reads q directly and uses it for FORS+C address domain separation (ci=q in the ADRS) and the Merkle auth path walk. No on-chain counter, no storage slot, no SSTORE.

The 1-byte q field is authenticated implicitly: a wrong q produces a wrong FORS+C public key via the ci=q domain separation, which produces a wrong Merkle root, which fails the root check. The signer cannot lie about q.

## 8. On-Chain Results

Full slot lifecycle tested on both Sepolia (ERC-4337 hybrid) and ethrex (EIP-8141 frame). Measurements with the balanced h=7 tree, Q_MAX=128:

| Metric                    | Frame (ethrex) | 4337 (Sepolia) |
| ------------------------- | -------------- | -------------- |
| Type 1 register           | 234K           | 323K           |
| Type 1 stateless fallback | 209K           | 300K           |
| Type 2 (any q, constant)  | 119K           | 176K           |
| Sig (Type 2, any q)       | 2,598 B        | 2,663 B        |

Compact-path verification gas is constant regardless of q, matching the balanced-tree design.

## 9. Security Summary

| Component                | Property          | Value                    |
| ------------------------ | ----------------- | ------------------------ |
| Compact path (FORS+C)    | One-time (r=1)    | 130-bit                  |
|                          | Double-sign (r=2) | 105-bit                  |
|                          | Five reuses (r=5) | 74-bit                   |
| Stateless fallback (C11) | At 2^14 sigs      | 128-bit                  |
|                          | At 2^18 sigs      | 104.5-bit                |
| Hybrid ECDSA             | Pre-quantum       | secp256k1                |
| Hash function            | Preimage          | keccak256, 128-bit       |
| Replay protection        | 4337 / Frame      | EntryPoint / Protocol nonce |
| Rollback resistance      | Device            | Burn-before-sign (NVRAM) |

## 10. Relation to Prior Work

|                    | SHRINCS [4]           | SHRIMPS [5]                 | JARDIN                          |
| ------------------ | --------------------- | --------------------------- | ------------------------------- |
| Compact path       | WOTS+C (one-time)     | Compact SPHINCS+            | FORS+C (few-time)               |
| Reuse tolerance    | None (catastrophic)   | Graceful (SPHINCS+ variant) | Ok for 2 use (105-bit at r=2)   |
| Compact sig        | 308 B (q=1)           | 2,564 B                     | 2,598 B (constant)              |
| Multi-device       | Single device         | Bounded (n_dev)             | Unlimited (2^256 slots)         |
| State coordination | Required              | Minimal (per-device budget) | None                            |
| On-chain state     | N/A (Bitcoin)         | N/A (Bitcoin)               | Slot mapping only               |
| Target             | Bitcoin (SHA-256)     | Bitcoin (SHA-256)           | EVM (keccak256)                 |
| Tree topology      | Spine (low-q optimal) | N/A                         | Balanced (high-q optimal)       |

* * *

## References

[1] R. Babbush, A. Zalcman, C. Gidney, M. Broughton, T. Khattar, H. Neven, T. Bergamaschi, J. Drake, and D. Boneh. "Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations." arXiv:2603.28846, 2026.

[2] N. Consigny. "SPHINCs-: Efficient Stateless Post-Quantum Signature Verification on the EVM." Companion paper, 2026.

[3] M. Kudinov and J. Nick. "Hash-based Signature Schemes for Bitcoin." Cryptology ePrint Archive, Paper 2025/2203, 2025.

[4] J. Nick. "SHRINCS: 324-byte Stateful Post-Quantum Signatures with Static Backups." Delving Bitcoin, 2025. https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158

[5] J. Nick. "SHRIMPS: 2.5 KB Post-Quantum Signatures across Multiple Stateful Devices." Delving Bitcoin, 2025. https://delvingbitcoin.org/t/shrimps-2-5-kb-post-quantum-signatures-across-multiple-stateful-devices/2355

[6] T. Roche, V. Lomne. "A Side Journey to Titan." SSTIC, 2021.

[7] National Institute of Standards and Technology. "Stateless Hash-Based Digital Signature Standard." FIPS 205, August 2024.

[8] T. Marchand. "Verity: Lean 4 to EVM Formally Verified Smart Contracts." LFG Labs, 2025.

[9] Y. Seurin. "CryptoSecProofs: Machine-Checked Cryptographic Security Proofs." https://github.com/yannickseurin/CryptoSecProofs

[10] EIP-8141: Frame Transactions. ethereum/EIPs.
