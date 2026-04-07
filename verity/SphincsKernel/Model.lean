import Contracts.Common

namespace SphincsKernel

open Verity
open Verity.EVM.Uint256

/--
A tiny arithmetic compression function used only to model the verified kernel.
It is intentionally simple: the goal is to prove exact execution equivalence,
not to make a cryptographic claim about the compression itself.
-/
def compress (left right : Uint256) : Uint256 :=
  add (mul left 65537) (add (mul right 257) 97)

/-- One Merkle step: place the sibling either on the left or on the right. -/
def step (acc sibling : Uint256) (siblingOnLeft : Bool) : Uint256 :=
  if siblingOnLeft then
    compress sibling acc
  else
    compress acc sibling

/--
Fixed-depth root reconstruction. This is the small deterministic kernel we want
the contract to implement exactly.
-/
def previewPathModel
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Uint256 :=
  let level0 := step leaf sibling0 sibling0OnLeft
  let level1 := step level0 sibling1 sibling1OnLeft
  let level2 := step level1 sibling2 sibling2OnLeft
  step level2 sibling3 sibling3OnLeft

/-- The acceptance condition is just “the reconstructed root equals the stored root”. -/
def verifyPathModel
    (expectedRoot leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Bool :=
  previewPathModel leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft == expectedRoot

end SphincsKernel
