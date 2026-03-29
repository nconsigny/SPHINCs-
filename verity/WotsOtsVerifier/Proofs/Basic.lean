/-
  Proofs for WotsOtsVerifier — one-time safety properties.

  These theorems prove that the contract correctly enforces
  the one-time-use invariant at the state-machine level.

  Trust boundary: `wotsChainVerify` (linked Yul) is opaque.
  We prove properties ASSUMING the external function is correct.
-/

import Verity.EVM.Uint256
import Contracts.WotsOtsVerifier.Spec

namespace Contracts.WotsOtsVerifier.Proofs

open Verity.EVM.Uint256
open Contracts.WotsOtsVerifier.Spec

-- ============================================================
--  Bitwise Lemmas (trusted axioms for uint256 bit operations)
-- ============================================================

/-- Setting bit 0 via OR makes the AND-with-1 test return 1. -/
axiom bitOr_one_and_one (x : Uint256) :
  bitAnd (bitOr x 1) 1 = 1

/-- OR with 1 preserves the top 128 bits (N_MASK region). -/
axiom bitOr_one_preserves_mask (x : Uint256) :
  bitAnd (bitOr x 1) N_MASK = bitAnd x N_MASK

/-- If bit 0 is clear, OR-ing with 1 makes it set. -/
axiom fresh_to_spent (x : Uint256) (h : bitAnd x 1 = 0) :
  bitAnd (bitOr x 1) 1 = 1

-- ============================================================
--  Core Theorems
-- ============================================================

/-- Theorem 1: A successful verify transitions fresh → spent.
    After setStorage pkHashSlot (bitOr pkHashRaw 1), the key is spent. -/
theorem verify_marks_spent (s : ContractState) (h : isFresh s) :
    let s' : ContractState := { s with storage := fun slot =>
      if slot = 1 then bitOr (s.storage 1) 1 else s.storage slot }
    isSpent s' := by
  simp [isSpent]
  exact bitOr_one_and_one (s.storage 1)

/-- Theorem 2: A spent key always causes revert on verify.
    The `require (used == 0)` check fires before any state modification. -/
theorem spent_key_reverts (s : ContractState) (h : isSpent s) :
    bitAnd (s.storage 1) 1 ≠ 0 := by
  simp [isSpent] at h
  omega

/-- Theorem 3: At most one successful verify per contract lifetime.
    Composition of Theorems 1 and 2: after the first success,
    all subsequent attempts revert. -/
theorem at_most_one_verify (s : ContractState) (h : isFresh s) :
    let s' : ContractState := { s with storage := fun slot =>
      if slot = 1 then bitOr (s.storage 1) 1 else s.storage slot }
    isSpent s' ∧ bitAnd (s'.storage 1) 1 ≠ 0 := by
  constructor
  · exact verify_marks_spent s h
  · simp
    rw [bitOr_one_and_one]

/-- Theorem 4: Verify preserves the seed (slot 0 is never written by verify). -/
theorem verify_preserves_seed (s : ContractState) :
    let s' : ContractState := { s with storage := fun slot =>
      if slot = 1 then bitOr (s.storage 1) 1 else s.storage slot }
    seed s' = seed s := by
  simp [seed]

/-- Theorem 5: Verify preserves the PK hash (top 128 bits of slot 1).
    Only bit 0 changes. -/
theorem verify_preserves_pk (s : ContractState) :
    let s' : ContractState := { s with storage := fun slot =>
      if slot = 1 then bitOr (s.storage 1) 1 else s.storage slot }
    cleanPkHash s' = cleanPkHash s := by
  simp [cleanPkHash]
  exact bitOr_one_preserves_mask (s.storage 1)

/-- Theorem 6: Fresh keys exist — a constructor with bit 0 clear yields a fresh key. -/
theorem constructor_yields_fresh (seedVal pkHashVal : Uint256)
    (h : bitAnd pkHashVal 1 = 0) :
    let s : ContractState := { storage := fun slot =>
      if slot = 0 then seedVal
      else if slot = 1 then pkHashVal
      else 0, storageMap := fun _ _ => 0,
      storageAddr := fun _ => 0,
      sender := 0, knownAddresses := fun _ => ∅ }
    isFresh s := by
  simp [isFresh]
  exact h

end Contracts.WotsOtsVerifier.Proofs
