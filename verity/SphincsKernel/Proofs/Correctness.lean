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
