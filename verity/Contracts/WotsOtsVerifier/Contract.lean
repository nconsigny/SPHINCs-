/-
  WotsOtsVerifier — Post-quantum one-time signature verifier.

  WOTS+C (checksum-less WOTS with grinding) verification for a smart contract
  wallet that enforces single-use keys. Parameters: w=16, n=128 bits, l=32,
  targetSum=240, z=0. Signature: 516 bytes.

  Architecture (same as Verity CryptoHash/Poseidon pattern):
  - EDSL: Contract monad with `callOracle` for the chain verification
  - CompilationModel: `Expr.externalCall "wotsChainVerify"` linked to Yul
  - Linked Yul: `external-libs/WotsChainVerify.yul`

  Storage layout:
    slot 0: pkSeed   (Uint256, top 128 bits meaningful)
    slot 1: pkHash   (Uint256, top 128 bits = PK, bit 0 = used flag)

  Reference: ePrint 2025/2203 (Blockstream SPHINCS+C)

  To build inside Verity framework:
    1. Clone https://github.com/Th0rgal/verity.git
    2. Copy this directory to Contracts/WotsOtsVerifier/
    3. Add `.andSubmodules `Contracts.WotsOtsVerifier` to lakefile.lean
    4. lake build Contracts.WotsOtsVerifier
-/

import Verity.Core
import Verity.Core.Semantics
import Verity.EVM.Uint256

namespace Contracts.WotsOtsVerifier

open Verity
open Verity.EVM.Uint256

-- ============================================================
--  Constants
-- ============================================================

/-- N_MASK: top 128 bits of a 256-bit word.
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000 -/
def N_MASK : Uint256 := Verity.Core.Uint256.ofNat (2^256 - 2^128)

-- ============================================================
--  Storage Slots
-- ============================================================

def pkSeedSlot : StorageSlot Uint256 := ⟨0⟩
def pkHashSlot : StorageSlot Uint256 := ⟨1⟩

-- ============================================================
--  Bitwise helpers (matching Contracts.Common signatures)
-- ============================================================

def bitAnd (a b : Uint256) : Uint256 := Verity.Core.Uint256.and a b
def bitOr (a b : Uint256) : Uint256 := Verity.Core.Uint256.or a b

-- ============================================================
--  External: WOTS+C chain verification (linked Yul)
-- ============================================================

/-- Placeholder for the linked external `wotsChainVerify`.
    In proofs: modeled as an opaque oracle.
    At compile time: linked to `WotsChainVerify.yul` via `--link`.

    Takes: (sigOffset, sigLen, message, seed) as Uint256 args.
    Returns: reconstructed PK (top 128 bits) or 0 on failure. -/
def wotsChainVerify (sigOffset sigLen message seed : Uint256) : Contract Uint256 := fun s =>
  ContractResult.success
    ((Verity.Env.ofWorld s).callOracle "wotsChainVerify" [sigOffset, sigLen, message, seed])
    s

-- ============================================================
--  State predicates
-- ============================================================

/-- The key is unused (bit 0 of pkHash is clear). -/
def isFresh (s : ContractState) : Prop :=
  bitAnd (s.storage 1) 1 = 0

/-- The key is used (bit 0 of pkHash is set). -/
def isSpent (s : ContractState) : Prop :=
  bitAnd (s.storage 1) 1 = 1

/-- Clean PK hash: top 128 bits of slot 1. -/
def cleanPkHash (s : ContractState) : Uint256 :=
  bitAnd (s.storage 1) N_MASK

-- ============================================================
--  Contract Functions
-- ============================================================

/-- Store seed and public key hash. -/
def setup (seed pkHash : Uint256) : Contract Unit := do
  setStorage pkSeedSlot seed
  setStorage pkHashSlot pkHash

/-- Verify a WOTS+C one-time signature.
    On success: marks key as used, returns 1.
    On failure: reverts.

    sigOffset/sigLen locate the signature in calldata. -/
def verify (message sigOffset sigLen : Uint256) : Contract Uint256 := do
  let seed ← getStorage pkSeedSlot
  let pkHashRaw ← getStorage pkHashSlot

  -- Check used flag (bit 0)
  let used := bitAnd pkHashRaw 1
  require (used == (0 : Uint256)) "Already used"

  let pkClean := bitAnd pkHashRaw N_MASK

  -- Call linked external chain verifier
  let computedPk ← wotsChainVerify sigOffset sigLen message seed

  -- Compare reconstructed PK with stored PK
  require (computedPk == pkClean) "Invalid signature"

  -- Mark used: set bit 0 of pkHash
  setStorage pkHashSlot (bitOr pkHashRaw 1)

  return (1 : Uint256)

/-- Check if the one-time key has been used. -/
def isUsed : Contract Uint256 := do
  let pkHashRaw ← getStorage pkHashSlot
  return (bitAnd pkHashRaw 1)

/-- Read the public seed. -/
def getPkSeed : Contract Uint256 := do
  getStorage pkSeedSlot

/-- Read the public key hash (with used flag in bit 0). -/
def getPkHash : Contract Uint256 := do
  getStorage pkHashSlot

end Contracts.WotsOtsVerifier
