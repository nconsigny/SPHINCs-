import Compiler.CompilationModel
import Sphincs.C4.Circuit

namespace Sphincs.C4.Frontier

open Compiler.CompilationModel
open Sphincs.C4.Circuit

def fields : List Field := [
  { name := "pkSeed", ty := .uint256, slot := some 0 }
, { name := "pkRoot", ty := .uint256, slot := some 1 }
]

def constructorSpec : ConstructorSpec := {
  params := [
    { name := "seed", ty := .bytes32 }
  , { name := "root", ty := .bytes32 }
  ]
  body := [
    .setStorage "pkSeed" (.param "seed")
  , .setStorage "pkRoot" (.param "root")
  ]
}

def verifyLocalObligations : List LocalObligation := [
  { name := "c4_sig_calldata_layout"
    obligation :=
      "The ABI anchors for `verify(bytes32,bytes)` must match the Solidity C4 verifier: sig length at calldata offset 0x44 and sig bytes at 0x64."
    proofStatus := .assumed }
, { name := "c4_top_hash_refinement"
    obligation :=
      "The `mstore` / `calldataload` / `keccak256` sequence in this frontier must match the `seed || root || R || message` framing of `src/SphincsWcFc30Asm.sol`."
    proofStatus := .assumed }
, { name := "c4_remaining_circuit_refinement"
    obligation :=
      "The remaining FORS+C, WOTS+C, and hypertree loops are not yet encoded here; this frontier currently fixes only the boundary and top-hash skeleton for C4."
    proofStatus := .assumed }
]

def verifyBody : List Stmt := [
  .letVar "sigLenAnchor" (.literal SigLenCalldataOffset)
, .letVar "sigBaseAnchor" (.literal SigBytesCalldataBase)
, .letVar "inputLen" (.literal HMsgInputLen)
, .letVar "sigLen" (.calldataload (.literal 68))
, .require (.eq (.localVar "sigLen") (.literal SigSize)) "Invalid sig length"
, .letVar "rWord" (.bitAnd (.calldataload (.literal 100)) (.literal NMask))
, .mstore (.literal 0) (.storage "pkSeed")
, .mstore (.literal 32) (.storage "pkRoot")
, .mstore (.literal 64) (.localVar "rWord")
, .mstore (.literal 96) (.param "message")
, .letVar "digest" (.keccak256 (.literal 0) (.literal HMsgInputLen))
, .letVar "htIdx" (.bitAnd (.shr (.literal 112) (.localVar "digest")) (.literal HtIdxMask))
, .returnValues [(.literal 1)]
]

def verifySpec : FunctionSpec := {
  name := "verify"
  params := [
    { name := "message", ty := .bytes32 }
  , { name := "sig", ty := .bytes }
  ]
  returnType := none
  returns := [.bool]
  isView := true
  localObligations := verifyLocalObligations
  body := verifyBody
}

def spec : CompilationModel := {
  name := "SphincsC4VerifierFrontier"
  fields := fields
  constructor := some constructorSpec
  functions := [verifySpec]
}

end Sphincs.C4.Frontier
