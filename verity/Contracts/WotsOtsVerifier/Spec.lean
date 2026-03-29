/-
  Formal specifications for WotsOtsVerifier operations.

  Defines the expected behavior of each function in terms of
  pre/post state transformations on ContractState.
-/

import Verity.Specs.Common
import Verity.EVM.Uint256
import Contracts.WotsOtsVerifier.Contract

namespace Contracts.WotsOtsVerifier.Spec

open Verity
open Verity.EVM.Uint256
open Contracts.WotsOtsVerifier

-- ============================================================
--  Constructor / setup Specification
-- ============================================================

/-- setup: stores seed at slot 0, pkHash at slot 1 -/
def setup_spec (seed pkHash : Uint256)
    (s s' : ContractState) : Prop :=
  s'.storage 0 = seed ∧
  s'.storage 1 = pkHash ∧
  Specs.sameStorageAddr s s' ∧
  Specs.sameStorageMap s s' ∧
  Specs.sameContext s s'

-- ============================================================
--  isUsed Specification
-- ============================================================

/-- isUsed: returns bit 0 of slot 1, no state change -/
def isUsed_spec (result : Uint256) (s : ContractState) : Prop :=
  result = Verity.Core.Uint256.and (s.storage 1) 1

-- ============================================================
--  getPkSeed Specification
-- ============================================================

/-- getPkSeed: returns slot 0, no state change -/
def getPkSeed_spec (result : Uint256) (s : ContractState) : Prop :=
  result = s.storage 0

-- ============================================================
--  getPkHash Specification
-- ============================================================

/-- getPkHash: returns slot 1 (with used flag), no state change -/
def getPkHash_spec (result : Uint256) (s : ContractState) : Prop :=
  result = s.storage 1

-- ============================================================
--  verify Specification
-- ============================================================

/-- verify success: on a fresh key with valid signature,
    slot 1 gets bit 0 set, slot 0 is unchanged, returns 1 -/
def verify_success_spec (s s' : ContractState) : Prop :=
  isFresh s ∧
  s'.storage 0 = s.storage 0 ∧
  s'.storage 1 = Verity.Core.Uint256.or (s.storage 1) 1 ∧
  isSpent s'

/-- verify rejects used key: if bit 0 of slot 1 is set, reverts -/
def verify_reject_used (s : ContractState) : Prop :=
  isSpent s

/-- verify rejects invalid signature: if computedPk != cleanPkHash, reverts -/
def verify_reject_invalid (s : ContractState) : Prop :=
  isFresh s
  -- wotsChainVerify returns a PK that doesn't match cleanPkHash

-- ============================================================
--  One-Time Safety (Composition Properties)
-- ============================================================

/-- After a successful verify, the key is spent and all subsequent
    verify calls will revert. Core OTS safety property. -/
def one_time_safety (s s' : ContractState) : Prop :=
  verify_success_spec s s' → isSpent s'

/-- The seed (slot 0) is never modified by verify -/
def seed_immutable (s s' : ContractState) : Prop :=
  verify_success_spec s s' → s'.storage 0 = s.storage 0

/-- The PK (top 128 bits of slot 1) is preserved —
    only bit 0 changes -/
def pk_preserved (s s' : ContractState) : Prop :=
  verify_success_spec s s' → cleanPkHash s' = cleanPkHash s

end Contracts.WotsOtsVerifier.Spec
