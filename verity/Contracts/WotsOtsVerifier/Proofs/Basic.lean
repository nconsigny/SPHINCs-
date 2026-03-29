/-
  Basic correctness proofs for WotsOtsVerifier contract.

  Proves that the one-time signature verifier correctly enforces
  the single-use invariant at the state-machine level.

  Trust boundary: `wotsChainVerify` (linked Yul) is opaque.
  We prove properties ASSUMING the external function behaves correctly.
-/

import Contracts.WotsOtsVerifier.Spec
import Contracts.WotsOtsVerifier.Invariants
import Verity.Proofs.Stdlib.Automation

namespace Contracts.WotsOtsVerifier.Proofs

open Verity
open Verity.EVM.Uint256
open Contracts.WotsOtsVerifier
open Contracts.WotsOtsVerifier.Spec
open Contracts.WotsOtsVerifier.Invariants

-- ============================================================
--  Storage Lemmas
-- ============================================================

theorem setStorage_pkSeed_updates_slot0 (s : ContractState) (value : Uint256) :
  let s' := ((setStorage pkSeedSlot value).run s).snd
  s'.storage 0 = value := by
  simp [pkSeedSlot]

theorem setStorage_pkHash_updates_slot1 (s : ContractState) (value : Uint256) :
  let s' := ((setStorage pkHashSlot value).run s).snd
  s'.storage 1 = value := by
  simp [pkHashSlot]

theorem setStorage_pkSeed_preserves_slot1 (s : ContractState) (value : Uint256) :
  let s' := ((setStorage pkSeedSlot value).run s).snd
  s'.storage 1 = s.storage 1 := by
  simp [pkSeedSlot]

theorem setStorage_pkHash_preserves_slot0 (s : ContractState) (value : Uint256) :
  let s' := ((setStorage pkHashSlot value).run s).snd
  s'.storage 0 = s.storage 0 := by
  simp [pkHashSlot]

-- ============================================================
--  setup Correctness
-- ============================================================

theorem setup_stores_seed (s : ContractState) (seed pkHash : Uint256) :
  let s' := ((setup seed pkHash).run s).snd
  s'.storage 0 = seed := by
  simp [setup, pkSeedSlot, pkHashSlot, getStorage, setStorage,
        Contract.run, ContractResult.snd, Verity.bind, Bind.bind]

theorem setup_stores_pkHash (s : ContractState) (seed pkHash : Uint256) :
  let s' := ((setup seed pkHash).run s).snd
  s'.storage 1 = pkHash := by
  simp [setup, pkSeedSlot, pkHashSlot, getStorage, setStorage,
        Contract.run, ContractResult.snd, Verity.bind, Bind.bind]

-- ============================================================
--  isUsed Correctness
-- ============================================================

theorem isUsed_reads_flag (s : ContractState) :
  let result := ((isUsed).run s).fst
  isUsed_spec result s := by
  sorry -- TODO: needs monadic unfolding of Contract return/bind

-- ============================================================
--  getPkSeed Correctness
-- ============================================================

theorem getPkSeed_reads_seed (s : ContractState) :
  let result := ((getPkSeed).run s).fst
  getPkSeed_spec result s := by
  simp [getPkSeed, getPkSeed_spec, pkSeedSlot,
        getStorage, Contract.run, ContractResult.fst, Verity.bind]

-- ============================================================
--  verify: One-Time Safety Properties
-- ============================================================

/-- After a successful verify, the new state has bit 0 of slot 1 set.
    This means `isSpent` holds on the post-state.
    (Assuming the Contract monad runs verify to success.) -/
theorem verify_success_implies_spent
    (s s' : ContractState)
    (h : verify_success_spec s s') :
    isSpent s' := by
  exact h.2.2.2

/-- If the key is already spent, the used flag check in verify
    will fail (bitAnd pkHash 1 ≠ 0). -/
theorem spent_key_fails_check (s : ContractState) (h : isSpent s) :
    bitAnd (s.storage 1) 1 ≠ 0 := by
  unfold isSpent at h
  rw [h]
  simp [bitAnd]
  decide

/-- At most one successful verify: composition of the above.
    After success (fresh → spent), any subsequent attempt finds
    the key spent, so the require check fails and reverts. -/
theorem at_most_one_verify
    (s s' : ContractState)
    (h_success : verify_success_spec s s') :
    isSpent s' ∧ bitAnd (s'.storage 1) 1 ≠ 0 := by
  constructor
  · exact verify_success_implies_spent s s' h_success
  · exact spent_key_fails_check s' (verify_success_implies_spent s s' h_success)

/-- Seed immutability: verify never changes slot 0. -/
theorem verify_preserves_seed
    (s s' : ContractState)
    (h : verify_success_spec s s') :
    s'.storage 0 = s.storage 0 := by
  exact h.2.1

/-- PK preservation: the top 128 bits of slot 1 are unchanged by verify.
    Only bit 0 is flipped. -/
theorem verify_preserves_pk_hash
    (s s' : ContractState)
    (h : verify_success_spec s s')
    (h_fresh : isFresh s) :
    cleanPkHash s' = cleanPkHash s := by
  simp [cleanPkHash, h.2.2.1]
  sorry -- requires bitwise arithmetic lemma: (x ||| 1) &&& N_MASK = x &&& N_MASK

/-- The used flag is monotone: once spent, always spent.
    Verify only transitions Fresh → Spent, never Spent → Fresh. -/
theorem used_flag_monotone
    (s s' : ContractState)
    (h_spent : isSpent s)
    (h_spec : verify_success_spec s s') :
    False := by
  have h_fresh := h_spec.1
  unfold isSpent bitAnd at h_spent
  unfold isFresh bitAnd at h_fresh
  simp [Verity.Core.Uint256.and] at h_spent h_fresh
  rw [h_spent] at h_fresh
  exact absurd h_fresh (by decide)

end Contracts.WotsOtsVerifier.Proofs
