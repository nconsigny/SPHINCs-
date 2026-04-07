import SphincsKernel.Spec
import Verity.Proofs.Stdlib.Automation

namespace SphincsKernel.Proofs

open Verity
open Verity.Specs
open Verity.Proofs.Stdlib.Automation
open SphincsKernel
open SphincsKernel.MerkleKernel
open SphincsKernel.Spec

theorem configureRoot_meets_spec (s : ContractState) (newRoot : Uint256) :
    let s' := ((configureRoot newRoot).run s).snd
    configureRoot_spec newRoot s s' := by
  verity_unfold configureRoot
  refine ⟨?_, ?_, ?_⟩
  · simp [pkRoot]
  · intro slotIdx h_neq
    simp [pkRoot, h_neq]
  · simp [Specs.sameAddrMapContext, Specs.sameStorageAddr, Specs.sameStorageArray,
      Specs.sameStorageMap, Specs.sameContext]

theorem currentRoot_meets_spec (s : ContractState) :
    let result := ((currentRoot).run s).fst
    currentRoot_spec result s := by
  verity_spec currentRoot_spec unfold currentRoot with pkRoot

theorem previewPath_returns_model
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool)
    (s : ContractState) :
    let result := ((previewPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).fst
    previewPath_spec result leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft := by
  cases sibling0OnLeft <;> cases sibling1OnLeft <;> cases sibling2OnLeft <;>
    cases sibling3OnLeft <;>
    simp [Contract.run, Verity.bind, Bind.bind, previewPath_spec, previewPath, previewPathModel,
      step, compress]

theorem previewPath_preserves_state
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool)
    (s : ContractState) :
    ((previewPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s).snd = s := by
  simp [previewPath]

theorem previewPackedPath_returns_model
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256)
    (s : ContractState) :
    let result := ((previewPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).fst
    previewPackedPath_spec result leaf sibling0 sibling1 sibling2 sibling3 directions := by
  simp [previewPackedPath_spec, previewPackedPath, previewPath, previewPackedPathModel, previewPathModel,
    step, compress, Contract.run, Verity.bind, Bind.bind]

theorem previewPackedPath_preserves_state
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256)
    (s : ContractState) :
    ((previewPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s).snd = s := by
  simp [previewPackedPath]

theorem verifyPath_meets_spec
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 : Uint256)
    (sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft : Bool) :
    let outcome := (verifyPath leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft).run s
    verifyPath_spec outcome.fst s outcome.snd leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft := by
  cases sibling0OnLeft <;> cases sibling1OnLeft <;> cases sibling2OnLeft <;>
    cases sibling3OnLeft <;>
    simp [Contract.run, Verity.bind, Bind.bind, verifyPath_spec, verifyPath, verifyPathModel,
      previewPathModel, step, compress]

theorem verifyPackedPath_meets_spec
    (s : ContractState)
    (leaf sibling0 sibling1 sibling2 sibling3 directions : Uint256) :
    let outcome := (verifyPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions).run s
    verifyPackedPath_spec outcome.fst s outcome.snd leaf sibling0 sibling1 sibling2 sibling3
      directions := by
  by_cases hCanonical : shr 4 directions == 0
  · simp [Contract.run, Verity.bind, Bind.bind, verifyPackedPath_spec, verifyPackedPath,
      verifyPackedPathModel, previewPackedPath, previewPath, previewPathModel, previewPackedPathModel,
      verifyWitnessModel, packedDirectionsCanonical, hCanonical, step, compress]
  · have hNonCanonical : shr 4 directions != 0 := by
      simp [hCanonical]
    simp [Contract.run, Verity.bind, Bind.bind, verifyPackedPath_spec, verifyPackedPath,
      verifyPackedPathModel, packedDirectionsCanonical, hNonCanonical, hCanonical]

end SphincsKernel.Proofs
