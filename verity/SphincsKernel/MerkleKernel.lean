import Contracts.Common
import Compiler.CheckContract

namespace SphincsKernel

open Contracts
open Verity hiding pure bind
open Verity.EVM.Uint256

verity_contract MerkleKernel where
  storage
    pkRoot : Uint256 := slot 0

  function stepNode (acc : Uint256) (sibling : Uint256) (siblingOnLeft : Bool) : Uint256 := do
    if siblingOnLeft then
      return add (mul sibling 65537) (add (mul acc 257) 97)
    else
      return add (mul acc 65537) (add (mul sibling 257) 97)

  function decodeDirectionBit (directions : Uint256) (bitIndex : Uint256) : Bool := do
    return bitAnd (shr bitIndex directions) 1 != 0

  function reconstructRoot
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        sibling0OnLeft : Bool, sibling1OnLeft : Bool, sibling2OnLeft : Bool, sibling3OnLeft : Bool) :
      Uint256 := do
    let level0 ← stepNode leaf sibling0 sibling0OnLeft
    let level1 ← stepNode level0 sibling1 sibling1OnLeft
    let level2 ← stepNode level1 sibling2 sibling2OnLeft
    stepNode level2 sibling3 sibling3OnLeft

  function configureRoot (newRoot : Uint256) : Unit := do
    setStorage pkRoot newRoot

  function currentRoot () : Uint256 := do
    let stored ← getStorage pkRoot
    return stored

  function previewPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        sibling0OnLeft : Bool, sibling1OnLeft : Bool, sibling2OnLeft : Bool, sibling3OnLeft : Bool) :
      Uint256 := do
    reconstructRoot leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft

  function previewPackedPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        directions : Uint256) :
      Uint256 := do
    let sibling0OnLeft ← decodeDirectionBit directions 0
    let sibling1OnLeft ← decodeDirectionBit directions 1
    let sibling2OnLeft ← decodeDirectionBit directions 2
    let sibling3OnLeft ← decodeDirectionBit directions 3
    reconstructRoot leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft

  function verifyPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        sibling0OnLeft : Bool, sibling1OnLeft : Bool, sibling2OnLeft : Bool, sibling3OnLeft : Bool) :
      Bool := do
    let stored ← getStorage pkRoot
    let candidate ← reconstructRoot leaf sibling0 sibling1 sibling2 sibling3
      sibling0OnLeft sibling1OnLeft sibling2OnLeft sibling3OnLeft
    return (candidate == stored)

  function verifyPackedPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        directions : Uint256) :
      Bool := do
    let stored ← getStorage pkRoot
    -- Only canonical packed witnesses are accepted; high bits are an explicit decode failure.
    let canonical := shr 4 directions == 0
    let candidate ← previewPackedPath leaf sibling0 sibling1 sibling2 sibling3 directions
    if canonical then
      return candidate == stored
    else
      return false

end SphincsKernel
