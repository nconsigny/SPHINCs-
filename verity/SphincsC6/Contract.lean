/-
  SphincsC6.Contract — C6 SPHINCS+ verifier contract model.

  Storage layout:
    slot 0: pkSeed   (Uint256, top 128 bits meaningful)
    slot 1: pkRoot   (Uint256, top 128 bits meaningful)

  Reference: ePrint 2025/2203 (Blockstream SPHINCS+C)
  C6 params: h=24 d=2 a=16 k=8 w=16 l=32 target_sum=240

  Axiom inventory (3 total — all cryptographic assumptions on keccak256):
    1. th_collision_resistant  (Hash.lean)
    2. th_domain_separated     (Hash.lean)
    3. thPair_collision_resistant (Hash.lean)
-/

import SphincsC6.Types
import SphincsC6.Hash
import SphincsC6.WotsC
import SphincsC6.ForsC
import SphincsC6.Hypertree

namespace SphincsC6

-- ============================================================
--  Digest Decomposition
-- ============================================================

def extractHtIdx (digest : UInt256) : Nat :=
  (digest / 2^(K * A)) % 2^H

-- ============================================================
--  Pure Functional Model (specification)
-- ============================================================

/-- Pure functional verify — the mathematical spec.
    This is what we prove properties about. -/
def verify (state : ContractState) (message : Hash128) (sig : SphincsC6Sig) : Bool :=
  let seed := state.pkSeed
  let root := state.pkRoot
  let digest := hMsg seed root sig.R message
  let htIdx := extractHtIdx digest
  let forsPk := forsVerify seed digest sig.fors
  let computedRoot := do
    let pk ← forsPk
    hypertreeVerify seed htIdx pk sig.htLayers
  match computedRoot with
  | some r => r == root
  | none => false

-- ============================================================
--  WOTS+C Digit Sum — PROVEN
-- ============================================================

/-- For any valid WOTS+C signature, the digest's base-16 digit sum equals
    TARGET_SUM (240). Follows directly from the `guard` in `wotsVerify`.
    (Security context: ePrint 2025/2203, Theorem 3) -/
theorem wots_c_digit_sum (seed : Hash128) (layer treeAddr leafIdx : Nat)
    (msgHash : Hash128) (sigma : Fin L → Hash128) (count : Nat) (pk : Hash128)
    (h : wotsVerify seed layer treeAddr leafIdx msgHash sigma count = some pk) :
    ∃ d, d = wotsDigest seed
              { layer := layer, treeAddr := treeAddr, adrsType := .wots, keyPair := leafIdx }
              msgHash count ∧
         digitSum d = TARGET_SUM := by
  simp [wotsVerify] at h
  split at h <;> simp_all
  rename_i hg
  exact ⟨_, rfl, hg⟩

-- ============================================================
--  FORS+C Forced-Zero — PROVEN
-- ============================================================

/-- For any valid FORS+C signature, the last FORS index is 0.
    Follows directly from the `guard (forcedZeroValid digest)` in `forsVerify`.
    (Security context: ePrint 2025/2203, Section 3.2) -/
theorem fors_c_forced_zero (seed : Hash128) (digest : UInt256) (sig : ForsCSig) (pk : Hash128)
    (h : forsVerify seed digest sig = some pk) :
    forcedZeroValid digest = true := by
  simp [forsVerify] at h
  split at h <;> simp_all

-- ============================================================
--  Security Notes (not formalized — paper proofs)
-- ============================================================

/-
  The following security properties are established in the paper (ePrint 2025/2203)
  and the parameter search (SPHINCS-Parameters/security.sage), NOT in Lean:

  1. EUF-CMA security: under collision resistance of keccak256, any forger can be
     reduced to a collision-finder. This is a computational reduction over PPT
     adversaries — not expressible in Lean's type theory without a probabilistic
     framework. (Section 4)

  2. Multi-signature bound (Fluhrer-Dang): after q signatures, forgery probability
     for FORS+C with k=8, a=16 is bounded by (q/2^16)^8 = q^8/2^128. At q=2^20,
     combined with the h=24 hypertree, security ≥ 128 bits. Computed by
     SPHINCS-Parameters/security.sage.

  These are inherently computational/probabilistic claims. Formalizing them would
  require a random oracle model in Lean (e.g., via CryptHOL or similar). This is
  outside the scope of Verity's deterministic EVM verification.
-/

end SphincsC6
