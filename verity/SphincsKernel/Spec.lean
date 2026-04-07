import Verity.Specs.Common
import Verity.Macro
import SphincsKernel.Model
import SphincsKernel.MerkleKernel

namespace SphincsKernel.Spec

open Verity
open Verity.Specs
open SphincsKernel

#gen_spec configureRoot_spec for (newRoot : Uint256) (0, (fun _ => newRoot), sameAddrMapContext)

def currentRoot_spec (result : Uint256) (s : ContractState) : Prop :=
  result = s.storage 0

def previewPath_spec
    (result : Uint256)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Prop :=
  result = previewPathModel leaf sibling0 sibling1 sibling2 sibling3
    sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft

def previewPackedPath_spec
    (result : Uint256)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    Prop :=
  result = previewPackedPathModel leaf sibling0 sibling1 sibling2 sibling3 directions

def verifyPath_spec
    (result : Bool)
    (s s' : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Prop :=
  result = verifyPathModel (s.storage 0) leaf sibling0 sibling1 sibling2 sibling3
    sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft ∧
  s' = s

def verifyPackedPath_spec
    (result : Bool)
    (s s' : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    Prop :=
  result = verifyPackedPathModel (s.storage 0) leaf sibling0 sibling1 sibling2 sibling3 directions ∧
  s' = s

end SphincsKernel.Spec
