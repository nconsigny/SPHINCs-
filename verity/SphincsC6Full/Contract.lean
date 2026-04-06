/-
  SphincsC6Full — Full SPHINCS+ C6 verification in Verity EDSL.
  No external oracle — the entire verification pipeline is expressed
  in the CompilationModel DSL and compiled + proven by Verity.

  C6: W+C_F+C h=24 d=2 a=16 k=8 w=16 l=32 target_sum=240
-/

import Compiler.CompilationModel

namespace Contracts.SphincsC6Full

open Compiler.CompilationModel

/-- N_MASK as a literal: top 128 bits of uint256. -/
private def N_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

/-- ADRS mask: clear chain position bits [24..27] = clear bits 32..63 of uint256. -/
private def CHAIN_POS_CLEAR_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF

/-- ADRS mask: clear height+index bits [24..31] = clear bits 0..63 of uint256. -/
private def TREE_HI_CLEAR_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000

-- Helper: Expr for common constants
private def e (n : Nat) : Expr := .literal n
private def v (s : String) : Expr := .localVar s
private def p (s : String) : Expr := .param s

def spec : CompilationModel := {
  name := "SphincsC6Full"
  fields := [
    { name := "pkSeed", ty := FieldType.uint256 },
    { name := "pkRoot", ty := FieldType.uint256 }
  ]

  «constructor» := some {
    params := [
      { name := "seed",   ty := ParamType.bytes32 },
      { name := "pkRoot", ty := ParamType.bytes32 }
    ]
    body := [
      .setStorage "pkSeed" (.constructorArg 0),
      .setStorage "pkRoot" (.constructorArg 1)
    ]
  }

  externals := []  -- No external oracle!

  functions := [
    -- ================================================================
    -- chainHash: complete a WOTS chain from startPos for `steps` steps
    -- chainHash(seed_is_in_mem, adrs, val, startPos, steps) -> val
    -- ================================================================
    { name := "chainHash"
      params := [
        { name := "adrs",     ty := ParamType.uint256 },
        { name := "val",      ty := ParamType.uint256 },
        { name := "startPos", ty := ParamType.uint256 },
        { name := "steps",    ty := ParamType.uint256 }
      ]
      returnType := some FieldType.uint256
      isInternal := true
      localObligations := [
        { name := "memory_layout"
          obligation := "Assumes seed is at memory[0x00]. ADRS written to memory[0x20], value to memory[0x40]. keccak256(0x00, 0x60) = Th(seed, adrs, val)."
          proofStatus := .assumed }
      ]
      body := [
        .letVar "result" (p "val"),
        .letVar "pos" (p "startPos"),
        .forEach "step" (p "steps") [
          -- Set chain position in ADRS
          .letVar "curAdrs" (.bitOr
            (.bitAnd (p "adrs") (e CHAIN_POS_CLEAR_MASK))
            (.shl (e 32) (v "pos"))),
          .mstore (e 0x20) (v "curAdrs"),
          .mstore (e 0x40) (v "result"),
          .assignVar "result" (.bitAnd (.keccak256 (e 0x00) (e 0x60)) (e N_MASK)),
          .assignVar "pos" (.add (v "pos") (e 1))
        ],
        .return (v "result")
      ]
    },

    -- ================================================================
    -- verify(bytes32 message, bytes sig) -> bool
    -- Full SPHINCS+ C6 verification — no oracle
    -- ================================================================
    { name := "verify"
      params := [
        { name := "message", ty := ParamType.bytes32 },
        { name := "sig",     ty := ParamType.bytes }
      ]
      returnType := some FieldType.uint256
      localObligations := [
        { name := "memory_layout"
          obligation := "Uses fixed memory layout: 0x00=seed, 0x20=ADRS, 0x40=input1, 0x60=input2, 0x80+=buffers. No free pointer usage."
          proofStatus := .assumed },
        { name := "calldataload_sig"
          obligation := "Signature starts at calldata offset 100 (4 selector + 32 message + 32 offset + 32 length). calldataload(68) = sig length."
          proofStatus := .assumed }
      ]
      body := [
        -- Load keys
        .letVar "seed" (.storage "pkSeed"),
        .letVar "root" (.storage "pkRoot"),

        -- Validate sig length
        .letVar "sigLen" (.calldataload (e 68)),
        .require (.eq (v "sigLen") (e 3352)) "Invalid sig length",

        -- SIG_BASE = 100 = 0x64
        .letVar "sigBase" (e 100),

        -- Setup memory: seed at 0x00
        .mstore (e 0x00) (v "seed"),

        -- ============================================================
        -- H_msg: digest = keccak256(seed || root || R || message || domain) — 160 bytes
        -- ============================================================
        .letVar "R" (.bitAnd (.calldataload (v "sigBase")) (e N_MASK)),
        .mstore (e 0x20) (v "root"),
        .mstore (e 0x40) (v "R"),
        .mstore (e 0x60) (p "message"),
        .mstore (e 0x80) (e 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
        .letVar "digest" (.keccak256 (e 0x00) (e 0xA0)),

        -- htIdx = (digest >> 128) & 0xFFFFFF
        .letVar "htIdx" (.bitAnd (.shr (e 128) (v "digest")) (e 0xFFFFFF)),

        -- ============================================================
        -- FORS+C: K=8, A=16
        -- ============================================================
        -- Check forced-zero: last index (bits 112-127) = 0
        .letVar "lastIdx" (.bitAnd (.shr (e 112) (v "digest")) (e 0xFFFF)),
        .require (.eq (v "lastIdx") (e 0)) "FORS+C forced-zero violated",

        -- 7 normal FORS trees
        .forEach "fi" (e 7) [
          .letVar "treeIdx" (.bitAnd (.shr (.mul (v "fi") (e 16)) (v "digest")) (e 0xFFFF)),
          -- Read secret: sigBase + 16 + fi*16
          .letVar "secretVal" (.bitAnd (.calldataload (.add (v "sigBase") (.add (e 16) (.mul (v "fi") (e 16))))) (e N_MASK)),
          -- Leaf ADRS: type=3, keyPair=fi, hashAddr=treeIdx
          .letVar "leafAdrs" (.bitOr (.shl (e 128) (e 3)) (.bitOr (.shl (e 96) (v "fi")) (v "treeIdx"))),
          .mstore (e 0x20) (v "leafAdrs"),
          .mstore (e 0x40) (v "secretVal"),
          .letVar "node" (.bitAnd (.keccak256 (e 0x00) (e 0x60)) (e N_MASK)),

          .letVar "treeAdrsBase" (.bitOr (.shl (e 128) (e 3)) (.shl (e 96) (v "fi"))),
          .letVar "pathIdx" (v "treeIdx"),
          -- Auth path base: sigBase + 144 + fi*256
          .letVar "authBase" (.add (v "sigBase") (.add (e 144) (.mul (v "fi") (e 256)))),

          -- Walk 16 auth levels
          .forEach "ah" (e 16) [
            .letVar "sibling" (.bitAnd (.calldataload (.add (v "authBase") (.mul (v "ah") (e 16)))) (e N_MASK)),
            .letVar "parentIdx" (.shr (e 1) (v "pathIdx")),
            .mstore (e 0x20) (.bitOr (v "treeAdrsBase") (.bitOr (.shl (e 32) (.add (v "ah") (e 1))) (v "parentIdx"))),
            .letVar "bit" (.bitAnd (v "pathIdx") (e 1)),
            -- Branchless left/right
            .mstore (e 0x40) (.bitXor (v "node") (.mul (.bitXor (v "node") (v "sibling")) (v "bit"))),
            .mstore (e 0x60) (.bitXor (v "sibling") (.mul (.bitXor (v "sibling") (v "node")) (v "bit"))),
            .assignVar "node" (.bitAnd (.keccak256 (e 0x00) (e 0x80)) (e N_MASK)),
            .assignVar "pathIdx" (v "parentIdx")
          ],

          -- Store FORS root at 0x80 + fi*32
          .mstore (.add (e 0x80) (.mul (v "fi") (e 0x20))) (v "node")
        ],

        -- Last tree (forced-zero): secret = root hash
        .letVar "lastSecret" (.bitAnd (.calldataload (.add (v "sigBase") (.add (e 16) (.mul (e 7) (e 16))))) (e N_MASK)),
        .mstore (e 0x20) (.bitOr (.shl (e 128) (e 3)) (.shl (e 96) (e 7))),
        .mstore (e 0x40) (v "lastSecret"),
        .mstore (.add (e 0x80) (.mul (e 7) (e 0x20))) (.bitAnd (.keccak256 (e 0x00) (e 0x60)) (e N_MASK)),

        -- Compress 8 FORS roots
        .mstore (e 0x20) (.shl (e 128) (e 4)),
        .forEach "ri" (e 8) [
          .mstore (.add (e 0x40) (.mul (v "ri") (e 0x20))) (.mload (.add (e 0x80) (.mul (v "ri") (e 0x20))))
        ],
        .letVar "currentNode" (.bitAnd (.keccak256 (e 0x00) (e 0x140)) (e N_MASK)),

        -- ============================================================
        -- Hypertree: D=2 layers
        -- ============================================================
        .letVar "idxTree" (v "htIdx"),
        .letVar "sigOff" (e 1936),  -- HT_START

        .forEach "layer" (e 2) [
          .letVar "idxLeaf" (.bitAnd (v "idxTree") (e 0xFFF)),
          .assignVar "idxTree" (.shr (e 12) (v "idxTree")),

          -- WOTS ADRS
          .letVar "wotsAdrs" (.bitOr (.shl (e 224) (v "layer")) (.bitOr (.shl (e 160) (v "idxTree")) (.shl (e 96) (v "idxLeaf")))),

          -- Read count
          .letVar "countOff" (.add (v "sigOff") (e 512)),
          .letVar "count" (.shr (e 224) (.calldataload (.add (v "sigBase") (v "countOff")))),

          -- WOTS digest
          .mstore (e 0x20) (v "wotsAdrs"),
          .mstore (e 0x40) (v "currentNode"),
          .mstore (e 0x60) (v "count"),
          .letVar "d" (.keccak256 (e 0x00) (e 0x80)),

          -- Validate digit sum = 240
          .letVar "digitSum" (e 0),
          .forEach "di" (e 32) [
            .assignVar "digitSum" (.add (v "digitSum") (.bitAnd (.shr (.mul (v "di") (e 4)) (v "d")) (e 0xF)))
          ],
          .require (.eq (v "digitSum") (e 240)) "WOTS+C sum violated",

          -- Complete 32 chains
          .forEach "ci" (e 32) [
            .letVar "digit" (.bitAnd (.shr (.mul (v "ci") (e 4)) (v "d")) (e 0xF)),
            .letVar "steps" (.sub (e 15) (v "digit")),
            .letVar "val" (.bitAnd (.calldataload (.add (v "sigBase") (.add (v "sigOff") (.mul (v "ci") (e 16))))) (e N_MASK)),
            .letVar "chainAdrs" (.bitOr (v "wotsAdrs") (.shl (e 64) (v "ci"))),

            -- Chain hash via internal function
            .mstore (e 0x00) (v "seed"),  -- ensure seed in memory
            .internalCallAssign ["chainResult"] "chainHash" [v "chainAdrs", v "val", v "digit", v "steps"],

            .mstore (.add (e 0x80) (.mul (v "ci") (e 0x20))) (v "chainResult")
          ],

          -- PK compression
          .letVar "pkAdrs" (.bitOr (.shl (e 224) (v "layer")) (.bitOr (.shl (e 160) (v "idxTree")) (.bitOr (.shl (e 128) (e 1)) (.shl (e 96) (v "idxLeaf"))))),
          .mstore (e 0x00) (v "seed"),
          .mstore (e 0x20) (v "pkAdrs"),
          .forEach "pi" (e 32) [
            .mstore (.add (e 0x40) (.mul (v "pi") (e 0x20))) (.mload (.add (e 0x80) (.mul (v "pi") (e 0x20))))
          ],
          .letVar "wotsPk" (.bitAnd (.keccak256 (e 0x00) (e 0x440)) (e N_MASK)),

          -- Merkle auth path (12 levels)
          .letVar "authOff" (.add (v "countOff") (e 4)),
          .letVar "treeAdrs" (.bitOr (.shl (e 224) (v "layer")) (.bitOr (.shl (e 160) (v "idxTree")) (.shl (e 128) (e 2)))),
          .letVar "merkleNode" (v "wotsPk"),
          .letVar "mIdx" (v "idxLeaf"),

          .forEach "mh" (e 12) [
            .letVar "mSibling" (.bitAnd (.calldataload (.add (v "sigBase") (.add (v "authOff") (.mul (v "mh") (e 16))))) (e N_MASK)),
            .letVar "mParent" (.shr (e 1) (v "mIdx")),
            .mstore (e 0x20) (.bitOr (.bitAnd (v "treeAdrs") (e TREE_HI_CLEAR_MASK)) (.bitOr (.shl (e 32) (.add (v "mh") (e 1))) (v "mParent"))),
            .letVar "mBit" (.bitAnd (v "mIdx") (e 1)),
            .mstore (e 0x40) (.bitXor (v "merkleNode") (.mul (.bitXor (v "merkleNode") (v "mSibling")) (v "mBit"))),
            .mstore (e 0x60) (.bitXor (v "mSibling") (.mul (.bitXor (v "mSibling") (v "merkleNode")) (v "mBit"))),
            .assignVar "merkleNode" (.bitAnd (.keccak256 (e 0x00) (e 0x80)) (e N_MASK)),
            .assignVar "mIdx" (v "mParent")
          ],

          .assignVar "currentNode" (v "merkleNode"),
          .assignVar "sigOff" (.add (v "authOff") (.mul (e 12) (e 16)))
        ],

        -- Final comparison
        .return (.eq (v "currentNode") (v "root"))
      ]
    },

    -- pkSeed() -> bytes32
    { name := "pkSeed"
      params := []
      returnType := some FieldType.uint256
      body := [.return (.storage "pkSeed")]
    },

    -- pkRoot() -> bytes32
    { name := "pkRoot"
      params := []
      returnType := some FieldType.uint256
      body := [.return (.storage "pkRoot")]
    }
  ]
}

end Contracts.SphincsC6Full
