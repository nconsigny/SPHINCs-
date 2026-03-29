/-
  State invariants for WotsOtsVerifier contract.

  Defines properties that should always hold, regardless of operations.
-/

import Verity.Specs.Common
import Verity.EVM.Uint256
import Contracts.WotsOtsVerifier.Contract

namespace Contracts.WotsOtsVerifier.Invariants

open Verity
open Verity.EVM.Uint256
open Contracts.WotsOtsVerifier

/-- Well-formed contract state:
    - Sender address is nonzero
    - Contract address is nonzero -/
structure WellFormedState (s : ContractState) : Prop where
  sender_nonzero : s.sender ≠ 0
  contract_nonzero : s.thisAddress ≠ 0

/-- Storage isolation: Operations on slots 0-1 don't affect other slots -/
def storage_isolated (s s' : ContractState) (slot : Nat) : Prop :=
  slot ≠ 0 → slot ≠ 1 → s'.storage slot = s.storage slot

/-- Address storage unchanged: Uint256 operations don't touch Address storage -/
abbrev addr_storage_unchanged := Specs.sameStorageAddr

/-- Mapping storage unchanged: This contract doesn't use mappings -/
abbrev map_storage_unchanged := Specs.sameStorageMap

/-- Contract context preserved -/
abbrev context_preserved := Specs.sameContext

/-- Complete state preservation except for slot 1 (pkHash with used flag):
    verify only modifies slot 1 bit 0; everything else is unchanged. -/
def state_preserved_except_pkHash (s s' : ContractState) : Prop :=
  s'.storage 0 = s.storage 0 ∧
  (∀ slot, slot ≠ 0 → slot ≠ 1 → s'.storage slot = s.storage slot) ∧
  addr_storage_unchanged s s' ∧
  map_storage_unchanged s s' ∧
  context_preserved s s'

/-- The used flag is monotone: once set, it stays set.
    This is the key safety invariant for one-time signatures. -/
def used_flag_monotone (s s' : ContractState) : Prop :=
  isSpent s → isSpent s'

end Contracts.WotsOtsVerifier.Invariants
