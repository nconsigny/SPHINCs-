import SphincsKernel.Proofs.Basic

namespace SphincsKernel.Proofs.Correctness

open Verity
open SphincsKernel
open SphincsKernel.MerkleKernel
open SphincsKernel.Spec
open SphincsKernel.Proofs

theorem verifyPath_sound
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool)
    (h :
      ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
        sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst = true) :
    previewPathModel leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft = s.storage 0 := by
  simp [verifyPath, previewPath, verifyPathModel, previewPathModel, beq_iff_eq] at h
  exact h

theorem verifyPath_iff_reconstructs_stored_root
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst = true ↔
      previewPathModel leaf sibling0 sibling1 sibling2 sibling3
        sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft = s.storage 0 := by
  simp [verifyPath, previewPath, verifyPathModel, previewPathModel, beq_iff_eq]

theorem verifyPath_iff_accepts_typed_witness
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst = true ↔
      verifyWitnessModel (s.storage 0)
        (mkWitness leaf sibling0 sibling1 sibling2 sibling3
          sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft) = true := by
  simp [verifyPath, verifyPathModel]

theorem verifyPath_complete
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool)
    (h :
      previewPathModel leaf sibling0 sibling1 sibling2 sibling3
        sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft = s.storage 0) :
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst = true := by
  simp [verifyPath, previewPath, verifyPathModel, previewPathModel, h, beq_iff_eq]

theorem verifyPath_rejects_wrong_root
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool)
    (h :
      previewPathModel leaf sibling0 sibling1 sibling2 sibling3
        sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft ≠ s.storage 0) :
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst = false := by
  simp [verifyPath, previewPath, verifyPathModel, previewPathModel, beq_iff_eq, h]

theorem verifyPath_preserves_state
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).snd = s := by
  simp [verifyPath, previewPath]

theorem previewPackedPath_decodes_witness
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    previewPackedPathModel leaf sibling0 sibling1 sibling2 sibling3 directions =
      previewWitnessModel
        (decodePackedWitness (mkPackedWitness leaf sibling0 sibling1 sibling2 sibling3 directions)) := by
  rfl

theorem verifyPackedPath_iff_decoded_witness_matches_root
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    ((verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).fst = true ↔
      packedDirectionsCanonical directions = true ∧
      previewWitnessModel
        (decodePackedWitness (mkPackedWitness leaf sibling0 sibling1 sibling2 sibling3 directions)) =
        s.storage 0 := by
  simp [verifyPackedPath, verifyPackedPathModel, verifyPackedPathModel, previewPackedPath,
    previewPath, previewPathModel, verifyWitnessModel, packedDirectionsCanonical, beq_iff_eq,
    step, compress]

theorem verifyPackedPath_iff_accepts_decoded_witness
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    ((verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).fst = true ↔
      packedDirectionsCanonical directions = true ∧
      verifyWitnessModel (s.storage 0)
        (decodePackedWitness (mkPackedWitness leaf sibling0 sibling1 sibling2 sibling3 directions)) =
        true := by
  simp [verifyPackedPath, verifyPackedPathModel, verifyWitnessModel, packedDirectionsCanonical]

theorem verifyPackedPath_rejects_noncanonical_directions
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256)
    (h : packedDirectionsCanonical directions = false) :
    ((verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).fst = false := by
  simp [verifyPackedPath, packedDirectionsCanonical, h]

theorem verifyPackedPath_preserves_state
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    ((verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).snd = s := by
  simp [verifyPackedPath]

theorem configure_then_verifyPacked_roundtrip
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    packedDirectionsCanonical directions = true →
    let expected := previewPackedPathModel leaf sibling0 sibling1 sibling2 sibling3 directions
    let s' := ((configureRoot expected).run s).snd
    ((verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s').fst = true := by
  intro hCanonical expected s'
  simp [configureRoot, verifyPackedPath, verifyPackedPathModel, previewPackedPathModel,
    verifyWitnessModel, packedDirectionsCanonical, pkRoot, hCanonical, previewPackedPath,
    previewPath, previewPathModel, step, compress]

theorem configure_then_verify_roundtrip
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    let expected := previewPathModel leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft
    let s' := ((configureRoot expected).run s).snd
    ((verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s').fst = true := by
  intro expected s'
  simp [configureRoot, verifyPath, previewPath, previewPathModel, verifyPathModel, pkRoot]

end SphincsKernel.Proofs.Correctness
