# SPHINCS+ Parameters Research — Paper Corpus

These are the papers and specifications referenced during SPHINCS+/SLH-DSA parameter exploration for EVM-optimized hash-based signatures.

---

## 1. Core Standards & Specifications

### FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- **Source:** NIST
- **URL:** https://csrc.nist.gov/pubs/fips/205/final
- **Relevance:** The NIST-standardized version of SPHINCS+. Defines the official parameter sets (SLH-DSA-128s/f, 192s/f, 256s/f) with FORS parameters (k, a), hypertree structure (h, d), and Winternitz parameter (w). Reference for all standard FORS k/a values used in our comparisons.

### SPHINCS+ Round 3.1 Specification
- **Authors:** Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, Schwabe
- **URL:** https://sphincs.org/data/sphincs+-r3.1-specification.pdf
- **Relevance:** The full SPHINCS+ specification submitted to NIST. Contains the security proofs, parameter selection rationale, the hypertree/FORS/WOTS+ architecture, and the 2^64 signature capacity requirement. Referenced extensively when analyzing keygen costs, stateless vs. stateful operation, and FORS few-time signature tolerance.

### Original SPHINCS (EUROCRYPT 2015)
- **Authors:** Bernstein, Hopwood, Hülsing, Lange, Niederhagen, Papachristodoulou, Schneider, Schwabe, Wilcox-O'Hearn
- **Relevance:** The original hash-based signature scheme using n=32 bytes. Referenced when discussing why Bernstein et al. chose n=32 initially and the evolution from SPHINCS to SPHINCS+.

---

## 2. Parameter Reduction & Optimization Papers

### "A Note on SPHINCS+ Parameter Sets" — Kölbl & Philipoom (Google/OpenTitan)
- **Authors:** Stefan Kölbl, Jade Philipoom
- **eprint:** https://eprint.iacr.org/2022/1725
- **NIST PDF:** https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/a-note-on-sphincs-plus-parameter-sets.pdf
- **Presented at:** 5th NIST PQC Standardization Conference, 2024
- **Relevance:** Key paper for reducing the 2^64 signature requirement. Proposes parameter sets targeting 2^20 signatures with up to 50% smaller signatures. Includes firmware signing case study on OpenTitan. Specific parameter: h=18, d=1, b(a)=24, k=6, w=16 → 3,264 bytes for 128-bit security. Extensively referenced for d=1 trick and WOTS+ compression.

### "Smaller SPHINCS+" — Fluhrer & Dang
- **Authors:** Scott Fluhrer, Quynh Dang
- **eprint:** https://eprint.iacr.org/2024/018
- **Archived version used:** https://eprint.iacr.org/archive/2024/018/1737032157.pdf
- **Relevance:** Core security formula for FORS forgery probability under multiple signatures. The Fluhrer-Dang equation (Equation 1) was used throughout our parameter sweeps to compute security degradation as a function of signatures per FORS instance. Basis for our comparison tables of pure FORS vs WOTS-FORS configurations with varying k (6–12), a (14–20), and w (8–64).

### Blockstream SPHINCS+ Parameter Exploration
- **Authors:** Blockstream Research
- **eprint:** https://eprint.iacr.org/2025/2203
- **GitHub:** https://github.com/BlockstreamResearch/SPHINCS-Parameters
- **Relevance:** Bitcoin-focused parameter optimization introducing WOTS+C (removes checksum chains via grinding), FORS+C (skips last auth path), PORS+FP (Octopus compression), and TL-WOTS-TW (remaps messages for faster verify). Uses n=16 bytes (Level 1) for size optimization. Heavily referenced when comparing d=1 vs d=2 hypertree approaches and evaluating truncated hash trade-offs for EVM.

---

## 3. EVM / Ethereum-Specific Hash-Based Signature Papers

### "poqeth" — Post-Quantum Ethereum Signatures (Kysil et al.)
- **Authors:** Kysil et al.
- **eprint:** https://eprint.iacr.org/2025/091
- **Venue:** ASIA CCS '25
- **GitHub:** https://github.com/ruslan-ilesik/poqeth
- **Relevance:** Directly measured W-OTS+, XMSS, SPHINCS+, and MAYO gas costs on Ethereum mainnet. Key findings: W-OTS+ w=4 at 222k gas, w=16 at 272k gas for on-chain; Naysayer optimistic mode down to 126k gas for w=16. XMSS at ~4.3M gas, SPHINCS+ at ~11.6M gas. Confirmed that keccak256 at 36 gas makes hash-based signatures surprisingly EVM-efficient.

### "Hash-Based Multi-Signatures for Post-Quantum Ethereum"
- **eprint:** https://eprint.iacr.org/2025/055
- **Relevance:** Proposes hash-based non-interactive multi-signatures for PQ proof-of-stake. Uses target sum Winternitz (eliminating checksum) within generalized XMSS. Directly relevant to consensus-layer PQ transition.

### leanSig — Lean Ethereum Signatures
- **GitHub:** https://github.com/leanEthereum/leanSig
- **Related paper:** https://eprint.iacr.org/2025/1332
- **Relevance:** Uses Poseidon2 hash over 31-bit prime field (KoalaBear/BabyBear). Security target kC=128, kQ=64 (NIST Level 1). Epoch-based signing model, incomparable encodings (alternative to WOTS checksum). Designed for ZK aggregation rather than native EVM verification. Referenced when comparing to our WOTS+Merkle approach.

### leanMultisig — ZK-Aggregated PQ Multi-Signatures
- **GitHub:** https://github.com/leanEthereum/leanMultisig
- **Relevance:** Aggregates 1775 XMSS signatures into a single STARK proof (~10s proving on M4 Max). Demonstrates the ZK-wrapped signature path for PQ Ethereum. Referenced when discussing STARK verification costs on EVM (~10-15M gas without precompile).

---

## 4. Shortened/Alternative Lattice Signature Papers (for comparison)

### "Shorter Lattice Signatures" — Gärtner
- **eprint:** https://eprint.iacr.org/2024/2052
- **Relevance:** Table 2 proposes shortened Fiat-Shamir lattice signatures (NOT Falcon) with sizes comparable to Falcon (1,059 bytes at 120-bit security). Referenced when comparing hash-based vs lattice-based on-chain costs. Uses NTWE (NTRU+LWE) with iterative rejection sampling.

### ETHFALCON / ETHDILITHIUM — Kohaku PQ Account Libraries
- **GitHub:** https://github.com/ZKNOXHQ/ETHFALCON
- **GitHub:** https://github.com/ZKNOXHQ/ETHDILITHIUM
- **Relevance:** EVM-optimized implementations. Falcon at 1.8M gas (with keccak optimization: 7M → 1.9M), ML-DSA at 6.6M gas (13.5M → 6.6M with keccak). Used as gas cost baselines when evaluating whether hash-based FORS/WOTS schemes are competitive.

---

## 5. Related Cryptographic Protocol Papers

### Vitalik's Quantum Emergency Hard Fork Proposal
- **URL:** https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901
- **Relevance:** Emergency recovery using STARK proofs of BIP-32 seed knowledge. Framework for PQ migration strategy. Referenced when discussing EOA migration paths.

### Bitcoin PQ Migration Draft BIP (Jameson Lopp)
- **URL:** https://github.com/jlopp/bips/blob/quantum_migration/bip-post-quantum-migration.mediawiki
- **Relevance:** Phase C proposes ZK proof of BIP-39 seed for quantum-safe UTXO recovery. Referenced for cross-chain PQ strategy comparison.

---

## 6. NIST Standards & Related Documents

### FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **Source:** NIST, August 2024
- **Relevance:** Finalized standard for CRYSTALS-Dilithium. ML-DSA-44/65/87 parameter sets. Referenced as baseline for EIP-8051 work.

### NIST PQC Call for Proposals — 2^64 Signature Requirement
- **Relevance:** The origin of the 2^64 signature capacity requirement that drove SPHINCS+ parameter choices. Understanding this requirement was critical for justifying reduced parameter sets.


### Smaller SLH-DSA  —  September 25th, 2025
- **URL:** https://csrc.nist.gov/csrc/media/presentations/2025/sphincs-smaller-parameter-sets/sphincs-dang_2.2.pdf
- **Relevance:** FIPS 205: SLH-DSA. Searches and evaluations of smaller SLH-DSA options and their applicability for certificate, software, and firmware signing.

---

## Summary of Key URLs

| #  | Paper/Resource                                           | URL                                                                                                    |
|----|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 1  | FIPS 205 (SLH-DSA)                                      | https://csrc.nist.gov/pubs/fips/205/final                                                             |
| 2  | SPHINCS+ R3.1 Spec                                      | https://sphincs.org/data/sphincs+-r3.1-specification.pdf                                               |
| 3  | Kölbl & Philipoom (Google)                              | https://eprint.iacr.org/2022/1725                                                                      |
| 4  | Kölbl & Philipoom (NIST conf PDF)                       | https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/a-note-on-sphincs-plus-parameter-sets.pdf |
| 5  | Fluhrer & Dang — Smaller SPHINCS+                       | https://eprint.iacr.org/2024/018                                                                       |
| 6  | Blockstream SPHINCS Parameters                          | https://eprint.iacr.org/2025/2203                                                                      |
| 7  | Blockstream GitHub                                      | https://github.com/BlockstreamResearch/SPHINCS-Parameters                                              |
| 8  | poqeth (Kysil et al.)                                   | https://eprint.iacr.org/2025/091                                                                       |
| 9  | Hash-Based Multi-Sigs for PQ Ethereum                   | https://eprint.iacr.org/2025/055                                                                       |
| 10 | leanSig paper                                           | https://eprint.iacr.org/2025/1332                                                                      |
| 11 | leanSig GitHub                                          | https://github.com/leanEthereum/leanSig                                                                |
| 12 | leanMultisig GitHub                                     | https://github.com/leanEthereum/leanMultisig                                                           |
| 13 | Gärtner — Shorter Lattice Sigs                          | https://eprint.iacr.org/2024/2052                                                                      |
| 14 | ETHFALCON                                               | https://github.com/ZKNOXHQ/ETHFALCON                                                                   |
| 15 | ETHDILITHIUM                                            | https://github.com/ZKNOXHQ/ETHDILITHIUM                                                                |
| 16 | Smaller SLH-DSA (Fluhrer & Dang NIST PQC 2025 slides)   | https://csrc.nist.gov/csrc/media/presentations/2025/sphincs-smaller-parameter-sets/sphincs-dang_2.2.pdf|
| 17 | poqeth GitHub                                           | https://github.com/ruslan-ilesik/poqeth                                                                |
| 18 | Vitalik — QE Hard Fork                                  | https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901          |
| 20 | Lopp — Bitcoin PQ BIP                                   | https://github.com/jlopp/bips/blob/quantum_migration/bip-post-quantum-migration.mediawiki              |


---

*Note: Papers #1–7 are the core SPHINCS+ parameter references. Papers #8–12 are Ethereum-specific implementations. Papers #13–15 are lattice-based comparisons. Papers #16–20 are related PQ migration/protocol papers that came up in parameter discussions.*
