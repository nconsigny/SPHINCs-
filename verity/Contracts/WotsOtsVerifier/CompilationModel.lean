/-
  CompilationModel for WotsOtsVerifier.

  Manual CompilationModel (same pattern as Verity's CryptoHash) because
  the contract uses a linked external Yul function (`wotsChainVerify`).

  To compile to Yul, add this spec to Contracts/Specs.lean in the Verity
  framework and run:
    lake exe verity-compiler --link examples/external-libs/WotsChainVerify.yul
-/

import Compiler.CompilationModel

namespace Contracts.WotsOtsVerifier.Compilation

open Compiler.CompilationModel

def wotsOtsVerifierSpec : CompilationModel := {
  name := "WotsOtsVerifier"
  fields := [
    { name := "pkSeed", ty := FieldType.uint256 },
    { name := "pkHash", ty := FieldType.uint256 }
  ]
  «constructor» := some {
    params := [
      { name := "seed", ty := ParamType.uint256 },
      { name := "pkHashInit", ty := ParamType.uint256 }
    ]
    body := [
      Stmt.setStorage "pkSeed" (Expr.constructorArg 0),
      Stmt.setStorage "pkHash" (Expr.constructorArg 1)
    ]
  }
  externals := [
    { name := "wotsChainVerify"
      params := [ParamType.uint256, ParamType.uint256, ParamType.uint256, ParamType.uint256]
      returnType := some ParamType.uint256
      axiomNames := ["wots_chain_deterministic", "wots_chain_collision_resistant"] }
  ]
  functions := [
    -- verify(message) -> uint256
    { name := "verify"
      params := [
        { name := "message", ty := ParamType.uint256 }
      ]
      returnType := some FieldType.uint256
      body := [
        Stmt.letVar "seed" (Expr.storage "pkSeed"),
        Stmt.letVar "pkHashRaw" (Expr.storage "pkHash"),
        Stmt.letVar "used" (Expr.bitAnd (Expr.localVar "pkHashRaw") (Expr.literal 1)),
        Stmt.require (Expr.eq (Expr.localVar "used") (Expr.literal 0)) "Already used",
        Stmt.letVar "pkClean" (Expr.bitAnd (Expr.localVar "pkHashRaw")
          (Expr.literal 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)),
        Stmt.letVar "sigLen" (Expr.calldataload (Expr.literal 68)),
        Stmt.letVar "sigOffset" (Expr.literal 100),
        Stmt.letVar "computedPk" (Expr.externalCall "wotsChainVerify"
          [Expr.localVar "sigOffset", Expr.localVar "sigLen",
           Expr.param "message", Expr.localVar "seed"]),
        Stmt.require (Expr.eq (Expr.localVar "computedPk") (Expr.localVar "pkClean"))
          "Invalid signature",
        Stmt.setStorage "pkHash" (Expr.bitOr (Expr.localVar "pkHashRaw") (Expr.literal 1)),
        Stmt.return (Expr.literal 1)
      ]
    },
    -- isUsed() -> uint256
    { name := "isUsed"
      params := []
      returnType := some FieldType.uint256
      body := [
        Stmt.return (Expr.bitAnd (Expr.storage "pkHash") (Expr.literal 1))
      ]
    },
    -- getPkSeed() -> uint256
    { name := "getPkSeed"
      params := []
      returnType := some FieldType.uint256
      body := [
        Stmt.return (Expr.storage "pkSeed")
      ]
    },
    -- getPkHash() -> uint256
    { name := "getPkHash"
      params := []
      returnType := some FieldType.uint256
      body := [
        Stmt.return (Expr.storage "pkHash")
      ]
    }
  ]
}

end Contracts.WotsOtsVerifier.Compilation
