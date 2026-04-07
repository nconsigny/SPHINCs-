import SphincsKernel.Spec

namespace SphincsKernel.Examples

open Verity
open Verity.EVM.Uint256
open SphincsKernel
open SphincsKernel.MerkleKernel

def sampleLeaf : Uint256 := 7
def sampleSibling0 : Uint256 := 11
def sampleSibling1 : Uint256 := 13
def sampleSibling2 : Uint256 := 17
def sampleSibling3 : Uint256 := 19
def sampleDirections : Uint256 := 10

def sampleWitness : MerkleWitness :=
  mkWitness sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
    false true false true

example :
    decodePackedWitness
      (mkPackedWitness sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
        sampleDirections) = sampleWitness := by
  native_decide

def acceptedRoot : Uint256 :=
  previewWitnessModel sampleWitness

example :
    verifyPathModel acceptedRoot sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      false true false true = true := by
  simp [acceptedRoot, verifyPathModel]

example :
    verifyPackedPathModel acceptedRoot sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      sampleDirections = true := by
  simp [acceptedRoot, verifyPackedPathModel, packedDirectionsCanonical, sampleDirections,
    verifyWitnessModel, sampleWitness, decodePackedWitness, mkPackedWitness, decodeDirectionBit,
    Contracts.bitAnd, beq_iff_eq]

example :
    verifyPathModel (add acceptedRoot 1) sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      false true false true = false := by
  simp [acceptedRoot, verifyPathModel, beq_iff_eq]

def configuredState : ContractState :=
  ((configureRoot acceptedRoot).run Verity.defaultState).snd

example :
    (configureRoot acceptedRoot).run Verity.defaultState =
      ContractResult.success () configuredState := by
  simp [configuredState, configureRoot, Contract.run]

example :
    (currentRoot).run configuredState = ContractResult.success acceptedRoot configuredState := by
  simp [configuredState, currentRoot, configureRoot, pkRoot, Contract.run]

example :
    (previewPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      false true false true).run Verity.defaultState =
      ContractResult.success acceptedRoot Verity.defaultState := by
  simp [acceptedRoot, previewPath, Contract.run]

example :
    (previewPackedPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      sampleDirections).run Verity.defaultState =
      ContractResult.success acceptedRoot Verity.defaultState := by
  simp [acceptedRoot, previewPackedPath, previewPackedPathModel, sampleDirections, sampleWitness,
    decodePackedWitness, mkPackedWitness, decodeDirectionBit, Contracts.bitAnd, Contract.run]

example :
    (verifyPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      false true false true).run configuredState =
      ContractResult.success true configuredState := by
  simp [configuredState, acceptedRoot, verifyPath, configureRoot, pkRoot, Contract.run]

example :
    (verifyPackedPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      sampleDirections).run configuredState =
      ContractResult.success true configuredState := by
  simp [configuredState, acceptedRoot, verifyPackedPath, configureRoot, verifyPackedPathModel,
    packedDirectionsCanonical, sampleDirections, pkRoot, decodePackedWitness, mkPackedWitness,
    decodeDirectionBit, Contracts.bitAnd, Contract.run, previewPackedPath, previewPath,
    previewPackedPathModel, previewPathModel, step, compress]

example :
    (verifyPackedPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      (sampleDirections + (shl 200 1))).run configuredState =
      ContractResult.success false configuredState := by
  simp [configuredState, acceptedRoot, verifyPackedPath, packedDirectionsCanonical, sampleDirections,
    Contract.run]

example :
    (verifyPath sampleLeaf sampleSibling0 sampleSibling1 sampleSibling2 sampleSibling3
      true true false true).run configuredState =
      ContractResult.success false configuredState := by
  simp [configuredState, acceptedRoot, verifyPath, configureRoot, pkRoot, Contract.run]

end SphincsKernel.Examples
