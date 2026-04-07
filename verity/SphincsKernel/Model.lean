import Contracts.Common

namespace SphincsKernel

open Contracts
open Verity
open Verity.EVM.Uint256

structure MerkleWitness where
  leaf : Uint256
  sibling0 : Uint256
  sibling1 : Uint256
  sibling2 : Uint256
  sibling3 : Uint256
  sibling0OnLeft : Bool
  sibling1OnLeft : Bool
  sibling2OnLeft : Bool
  sibling3OnLeft : Bool
deriving DecidableEq, Repr

structure PackedMerkleWitness where
  leaf : Uint256
  sibling0 : Uint256
  sibling1 : Uint256
  sibling2 : Uint256
  sibling3 : Uint256
  directions : Uint256
deriving DecidableEq, Repr

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

def mkWitness
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    MerkleWitness :=
  { leaf, sibling0, sibling1, sibling2, sibling3,
    sibling0OnLeft, sibling1OnLeft, sibling2OnLeft, sibling3OnLeft }

def mkPackedWitness
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    PackedMerkleWitness :=
  { leaf, sibling0, sibling1, sibling2, sibling3, directions }

/-- Directions are packed in the low 4 bits of `directions`, one bit per level. -/
def decodeDirectionBit (directions bitIndex : Uint256) : Bool :=
  bitAnd (shr bitIndex directions) 1 != 0

def decodePackedWitness (packed : PackedMerkleWitness) : MerkleWitness :=
  { leaf := packed.leaf
    sibling0 := packed.sibling0
    sibling1 := packed.sibling1
    sibling2 := packed.sibling2
    sibling3 := packed.sibling3
    sibling0OnLeft := decodeDirectionBit packed.directions 0
    sibling1OnLeft := decodeDirectionBit packed.directions 1
    sibling2OnLeft := decodeDirectionBit packed.directions 2
    sibling3OnLeft := decodeDirectionBit packed.directions 3 }

/--
Canonical packed witnesses use only the low 4 bits for directions.
Higher bits are malformed encoding noise: they may still decode to a typed witness,
but the acceptance API rejects them explicitly.
-/
def packedDirectionsCanonical (directions : Uint256) : Bool :=
  shr 4 directions == 0

def previewWitnessModel (witness : MerkleWitness) : Uint256 :=
  let level0 := step witness.leaf witness.sibling0 witness.sibling0OnLeft
  let level1 := step level0 witness.sibling1 witness.sibling1OnLeft
  let level2 := step level1 witness.sibling2 witness.sibling2OnLeft
  step level2 witness.sibling3 witness.sibling3OnLeft

def verifyWitnessModel (expectedRoot : Uint256) (witness : MerkleWitness) : Bool :=
  previewWitnessModel witness == expectedRoot

/--
Fixed-depth root reconstruction. This is the small deterministic kernel we want
the contract to implement exactly.
-/
def previewPathModel
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Uint256 :=
  previewWitnessModel <|
    mkWitness leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft

def previewPackedPathModel
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    Uint256 :=
  previewWitnessModel <|
    decodePackedWitness (mkPackedWitness leaf sibling0 sibling1 sibling2 sibling3 directions)

/-- The acceptance condition is just “the reconstructed root equals the stored root”. -/
def verifyPathModel
    (expectedRoot leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    Bool :=
  verifyWitnessModel expectedRoot <|
    mkWitness leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft

def verifyPackedPathModel
    (expectedRoot leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    Bool :=
  packedDirectionsCanonical directions &&
    verifyWitnessModel expectedRoot
      (decodePackedWitness (mkPackedWitness leaf sibling0 sibling1 sibling2 sibling3 directions))

end SphincsKernel
