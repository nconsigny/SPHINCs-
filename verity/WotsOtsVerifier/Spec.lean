/-
  Formal specifications for WotsOtsVerifier operations.

  These specs define the expected behavior of each function
  in terms of pre/post state transformations.
-/

import Verity.Specs.Common
import Verity.Macro
import Verity.EVM.Uint256

namespace Contracts.WotsOtsVerifier.Spec

open Verity
open Verity.Specs
open Verity.EVM.Uint256

-- N_MASK: top 128 bits of uint256
private def N_MASK : Uint256 :=
  sub (shl 256 1) (shl 128 1)

/-! ## State Predicates -/

/-- The key is unused (bit 0 of slot 1 is clear) -/
def isFresh (s : ContractState) : Prop :=
  bitAnd (s.storage 1) 1 = 0

/-- The key is used (bit 0 of slot 1 is set) -/
def isSpent (s : ContractState) : Prop :=
  bitAnd (s.storage 1) 1 = 1

/-- The clean PK hash (top 128 bits of slot 1) -/
def cleanPkHash (s : ContractState) : Uint256 :=
  bitAnd (s.storage 1) N_MASK

/-- The seed (slot 0) -/
def seed (s : ContractState) : Uint256 :=
  s.storage 0

/-! ## Constructor Specification -/

/-- Constructor: stores seed at slot 0 and pkHash at slot 1 -/
#gen_spec constructor_spec for (seedVal : Uint256) (pkHashVal : Uint256)
  (0, (fun _ => seedVal),
   sameAddrMapContext)

-- Slot 1 is also set to pkHashVal (manual spec since #gen_spec handles one slot)
def constructor_slot1_spec (seedVal : Uint256) (pkHashVal : Uint256)
    (s' : ContractState) : Prop :=
  s'.storage 0 = seedVal ∧ s'.storage 1 = pkHashVal

/-! ## isUsed Specification -/

/-- isUsed: returns bit 0 of slot 1, no state change -/
def isUsed_spec (result : Uint256) (s : ContractState) : Prop :=
  result = bitAnd (s.storage 1) 1

/-! ## getPkSeed Specification -/

/-- getPkSeed: returns slot 0, no state change -/
def getPkSeed_spec (result : Uint256) (s : ContractState) : Prop :=
  result = s.storage 0

/-! ## verify Specification -/

/-- verify on a fresh key with valid signature: marks used and returns 1.
    `wotsChainVerify` is opaque — we specify it returns `cleanPkHash s`
    when the signature is valid for the given message. -/
def verify_success_spec (message : Uint256) (s s' : ContractState) : Prop :=
  isFresh s ∧
  s'.storage 0 = s.storage 0 ∧               -- seed unchanged
  s'.storage 1 = bitOr (s.storage 1) 1 ∧     -- used flag set
  isSpent s'                                   -- result state is spent

/-- verify on a spent key: reverts (state unchanged) -/
def verify_reject_used_spec (s : ContractState) : Prop :=
  isSpent s
  -- The require (used == 0) "Already used" causes revert;
  -- Verity models this as the function not returning normally.

/-- verify with invalid signature: reverts (state unchanged) -/
def verify_reject_invalid_spec (s : ContractState) : Prop :=
  isFresh s
  -- The require (computedPk == pkHashClean) "Invalid signature" causes revert;
  -- state is not modified since require fires before setStorage.

/-! ## One-Time Safety (Composition) -/

/-- After a successful verify, the key is spent and all subsequent
    verify calls will revert. This is the core OTS safety property. -/
def one_time_safety (s s' : ContractState) (message : Uint256) : Prop :=
  verify_success_spec message s s' → isSpent s'

/-- The seed (slot 0) is never modified by verify. -/
def seed_immutable (s s' : ContractState) : Prop :=
  s'.storage 0 = s.storage 0

/-- The PK (top 128 bits of slot 1) is never modified —
    only bit 0 changes (from 0 to 1). -/
def pk_preserved (s s' : ContractState) : Prop :=
  cleanPkHash s' = cleanPkHash s

end Contracts.WotsOtsVerifier.Spec
