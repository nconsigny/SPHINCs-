/-
  CompilationModel for SphincsC6 Verifier.

  Manual CompilationModel (same pattern as Verity's CryptoHash) because
  the contract uses a linked external Yul function (`sphincsC6Verify`).

  To compile to Yul:
    1. Add this spec to Contracts/Specs.lean in the Verity framework
    2. Run: lake exe verity-compiler --link external-libs/SphincsC6Verify.yul

  The resulting bytecode should match SphincsC6Asm.sol's behavior.
-/

-- NOTE: This file uses the Verity compiler's CompilationModel types.
-- It does NOT compile standalone — it must be built inside the Verity framework.
-- Import path when inside Verity:
--   import Compiler.CompilationModel

-- For standalone reference, the model is defined as comments + pseudo-Lean:

/-
namespace SphincsC6.Compilation

open Compiler.CompilationModel

def sphincsC6VerifierSpec : CompilationModel := {
  name := "SphincsC6Verifier"

  -- Storage: 2 slots
  fields := [
    { name := "pkSeed", ty := FieldType.uint256 },
    { name := "pkRoot", ty := FieldType.uint256 }
  ]

  -- Constructor(bytes32 _seed, bytes32 _root)
  «constructor» := some {
    params := [
      { name := "seed",   ty := ParamType.uint256 },
      { name := "pkRoot", ty := ParamType.uint256 }
    ]
    body := [
      Stmt.setStorage "pkSeed" (Expr.constructorArg 0),
      Stmt.setStorage "pkRoot" (Expr.constructorArg 1)
    ]
  }

  -- External: full SPHINCS+ C6 verification (linked Yul)
  -- Takes the full signature calldata + message + seed
  -- Returns the computed Merkle root (or 0 on failure)
  externals := [
    { name := "sphincsC6Verify"
      params := [ParamType.uint256, ParamType.uint256, ParamType.uint256]
      -- params: (sigOffset/sigLen packed, message, seed)
      returnType := some ParamType.uint256
      axiomNames := [
        "keccak_collision_resistant",
        "keccak_domain_separated",
        "wots_c_digit_sum_invariant",
        "fors_c_forced_zero"
      ]
    }
  ]

  functions := [
    -- verify(bytes32 message, bytes sig) -> bool
    { name := "verify"
      params := [
        { name := "message", ty := ParamType.bytes32 },
        { name := "sig",     ty := ParamType.bytes }
      ]
      returnType := some FieldType.uint256
      body := [
        -- Load state
        Stmt.letVar "seed" (Expr.storage "pkSeed"),
        Stmt.letVar "root" (Expr.storage "pkRoot"),

        -- Validate signature length = 3352
        Stmt.letVar "sigLen" (Expr.calldataload (Expr.literal 68)),
        Stmt.require (Expr.eq (Expr.localVar "sigLen") (Expr.literal 3352))
          "Invalid sig length",

        -- Call external verifier: sphincsC6Verify(sigOffset, message, seed)
        -- sigOffset = 100 (past selector + message + offset + length)
        Stmt.letVar "computedRoot" (Expr.externalCall "sphincsC6Verify"
          [Expr.literal 100, Expr.param "message", Expr.localVar "seed"]),

        -- Mask to N bits (top 128)
        Stmt.letVar "maskedRoot" (Expr.bitAnd (Expr.localVar "computedRoot")
          (Expr.literal 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)),

        -- Compare with stored root
        Stmt.letVar "valid" (Expr.eq (Expr.localVar "maskedRoot") (Expr.localVar "root")),

        -- Return 1 if valid, 0 otherwise
        Stmt.return (Expr.localVar "valid")
      ]
    },

    -- pkSeed() -> bytes32
    { name := "pkSeed"
      params := []
      returnType := some FieldType.uint256
      body := [
        Stmt.return (Expr.storage "pkSeed")
      ]
    },

    -- pkRoot() -> bytes32
    { name := "pkRoot"
      params := []
      returnType := some FieldType.uint256
      body := [
        Stmt.return (Expr.storage "pkRoot")
      ]
    }
  ]
}

end SphincsC6.Compilation
-/

-- Standalone version for type-checking without Verity imports:
namespace SphincsC6.Compilation

/-- The compilation model is defined above as comments.
    When building inside Verity, uncomment the code and add:
      import Compiler.CompilationModel
    This file serves as the specification for the Verity compiler. -/
def placeholder := "See comments above for CompilationModel definition"

end SphincsC6.Compilation
