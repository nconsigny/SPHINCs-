import Contracts.Common
import Compiler.CheckContract

namespace SphincsKernel

open Contracts
open Verity hiding pure bind
open Verity.EVM.Uint256

verity_contract MerkleKernel where
  storage
    pkRoot : Uint256 := slot 0

  function configureRoot (newRoot : Uint256) : Unit := do
    setStorage pkRoot newRoot

  function currentRoot () : Uint256 := do
    let stored ← getStorage pkRoot
    return stored

  function previewPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        sibling0OnLeft : Bool, sibling1OnLeft : Bool, sibling2OnLeft : Bool, sibling3OnLeft : Bool) :
      Uint256 := do
    let mut level0 := 0
    if sibling0OnLeft then
      level0 := add (mul sibling0 65537) (add (mul leaf 257) 97)
    else
      level0 := add (mul leaf 65537) (add (mul sibling0 257) 97)
    let mut level1 := 0
    if sibling1OnLeft then
      level1 := add (mul sibling1 65537) (add (mul level0 257) 97)
    else
      level1 := add (mul level0 65537) (add (mul sibling1 257) 97)
    let mut level2 := 0
    if sibling2OnLeft then
      level2 := add (mul sibling2 65537) (add (mul level1 257) 97)
    else
      level2 := add (mul level1 65537) (add (mul sibling2 257) 97)
    let mut level3 := 0
    if sibling3OnLeft then
      level3 := add (mul sibling3 65537) (add (mul level2 257) 97)
    else
      level3 := add (mul level2 65537) (add (mul sibling3 257) 97)
    return level3

  function previewPackedPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        directions : Uint256) :
      Uint256 := do
    let sibling0OnLeft := bitAnd directions 1 != 0
    let sibling1OnLeft := bitAnd (shr 1 directions) 1 != 0
    let sibling2OnLeft := bitAnd (shr 2 directions) 1 != 0
    let sibling3OnLeft := bitAnd (shr 3 directions) 1 != 0
    let mut level0 := 0
    if sibling0OnLeft then
      level0 := add (mul sibling0 65537) (add (mul leaf 257) 97)
    else
      level0 := add (mul leaf 65537) (add (mul sibling0 257) 97)
    let mut level1 := 0
    if sibling1OnLeft then
      level1 := add (mul sibling1 65537) (add (mul level0 257) 97)
    else
      level1 := add (mul level0 65537) (add (mul sibling1 257) 97)
    let mut level2 := 0
    if sibling2OnLeft then
      level2 := add (mul sibling2 65537) (add (mul level1 257) 97)
    else
      level2 := add (mul level1 65537) (add (mul sibling2 257) 97)
    let mut level3 := 0
    if sibling3OnLeft then
      level3 := add (mul sibling3 65537) (add (mul level2 257) 97)
    else
      level3 := add (mul level2 65537) (add (mul sibling3 257) 97)
    return level3

  function verifyPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        sibling0OnLeft : Bool, sibling1OnLeft : Bool, sibling2OnLeft : Bool, sibling3OnLeft : Bool) :
      Bool := do
    let stored ← getStorage pkRoot
    let mut level0 := 0
    if sibling0OnLeft then
      level0 := add (mul sibling0 65537) (add (mul leaf 257) 97)
    else
      level0 := add (mul leaf 65537) (add (mul sibling0 257) 97)
    let mut level1 := 0
    if sibling1OnLeft then
      level1 := add (mul sibling1 65537) (add (mul level0 257) 97)
    else
      level1 := add (mul level0 65537) (add (mul sibling1 257) 97)
    let mut level2 := 0
    if sibling2OnLeft then
      level2 := add (mul sibling2 65537) (add (mul level1 257) 97)
    else
      level2 := add (mul level1 65537) (add (mul sibling2 257) 97)
    let mut candidate := 0
    if sibling3OnLeft then
      candidate := add (mul sibling3 65537) (add (mul level2 257) 97)
    else
      candidate := add (mul level2 65537) (add (mul sibling3 257) 97)
    return (candidate == stored)

  function verifyPackedPath
      (leaf : Uint256, sibling0 : Uint256, sibling1 : Uint256, sibling2 : Uint256, sibling3 : Uint256,
        directions : Uint256) :
      Bool := do
    let stored ← getStorage pkRoot
    -- Only canonical packed witnesses are accepted; high bits are an explicit decode failure.
    let canonical := shr 4 directions == 0
    let sibling0OnLeft := bitAnd directions 1 != 0
    let sibling1OnLeft := bitAnd (shr 1 directions) 1 != 0
    let sibling2OnLeft := bitAnd (shr 2 directions) 1 != 0
    let sibling3OnLeft := bitAnd (shr 3 directions) 1 != 0
    let mut level0 := 0
    if sibling0OnLeft then
      level0 := add (mul sibling0 65537) (add (mul leaf 257) 97)
    else
      level0 := add (mul leaf 65537) (add (mul sibling0 257) 97)
    let mut level1 := 0
    if sibling1OnLeft then
      level1 := add (mul sibling1 65537) (add (mul level0 257) 97)
    else
      level1 := add (mul level0 65537) (add (mul sibling1 257) 97)
    let mut level2 := 0
    if sibling2OnLeft then
      level2 := add (mul sibling2 65537) (add (mul level1 257) 97)
    else
      level2 := add (mul level1 65537) (add (mul sibling2 257) 97)
    let mut candidate := 0
    if sibling3OnLeft then
      candidate := add (mul sibling3 65537) (add (mul level2 257) 97)
    else
      candidate := add (mul level2 65537) (add (mul sibling3 257) 97)
    return (mul (boolToWord canonical) (boolToWord (candidate == stored)) != 0)

end SphincsKernel
