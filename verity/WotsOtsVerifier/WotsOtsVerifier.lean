/-
  WotsOtsVerifier — Verity contract: WOTS+C one-time signature verifier.

  This is a real `verity_contract` that implements a post-quantum one-time
  signature wallet using WOTS+C (ePrint 2025/2203). The heavy chain-hash
  computation is linked as external Yul (`wots_chain_verify.yul`);
  the wallet logic (storage, used-flag, access control) is proven in Lean.

  Parameters: w=16, n=128 bits, l=32, targetSum=240, sig=516 bytes.

  Storage layout:
    slot 0: pkSeed   (bytes32, top 128 bits meaningful)
    slot 1: pkHash   (bytes32, top 128 bits = PK, bit 0 = used flag)

  External linked Yul function:
    wotsChainVerify(sigOffset, sigLen, message, seed) -> computedPk
      Performs digest computation, digit extraction, 32 chain completions,
      and PK compression.  Returns the reconstructed PK (top 128 bits)
      or 0 on constraint violation.

  Compile:
    lake exe verity-compiler --link verity/wots_chain_verify.yul \
      -o artifacts/yul/WotsOtsVerifier.yul
-/

import Contracts.Common

namespace Contracts

open Verity hiding pure bind
open Verity.EVM.Uint256
open Verity.Stdlib.Math

-- N_MASK: top 128 bits of a 256-bit word
-- 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
private def N_MASK : Uint256 :=
  sub (shl 256 1) (shl 128 1)

verity_contract WotsOtsVerifier where
  storage
    pkSeedSlot : Uint256 := slot 0
    pkHashSlot : Uint256 := slot 1

  constructor (seed : Uint256, pkHash : Uint256) := do
    setStorage pkSeedSlot seed
    setStorage pkHashSlot pkHash

  -- External linked function: WOTS+C chain verification
  -- Implemented in wots_chain_verify.yul, linked at compile time.
  -- Returns the reconstructed PK, or 0 on constraint violation.
  external wotsChainVerify (sigOffset : Uint256, sigLen : Uint256,
                            message : Uint256, seed : Uint256) : Uint256

  /-- Verify a WOTS+C one-time signature.
      Reads the 516-byte signature from calldata after the message parameter.
      On success, marks the key as used (bit 0 of pkHash) and returns 1.
      On failure (invalid sig, wrong PK, already used), returns 0.
  -/
  function verify (message : Uint256)
    local_obligations [
      calldata_layout := assumed
        "Signature bytes follow the message parameter in calldata: "
        ++ "selector(4) + message(32) + offset(32) + length(32) + sig(516). "
        ++ "The calldataload at offset 68 yields the sig length, "
        ++ "and sig data starts at calldataload offset 100."
    ]
    : Uint256 := do
    -- Load state
    let seed ← getStorage pkSeedSlot
    let pkHashRaw ← getStorage pkHashSlot

    -- Check used flag (bit 0)
    let used := bitAnd pkHashRaw 1
    require (used == 0) "Already used"

    let pkHashClean := bitAnd pkHashRaw N_MASK

    -- Read signature length from calldata
    -- ABI layout: selector(4) + message(32) + bytes_offset(32) + bytes_length(32) + data
    -- sig length is at calldata offset 68 (4+32+32)
    let sigLen := calldataload 68

    -- Signature data offset in calldata = 100 (4+32+32+32)
    let sigOffset := 100

    -- Call linked external verifier
    -- This performs: digest computation, digit extraction + sum check,
    -- 32 chain completions, PK compression. Returns reconstructed PK or 0.
    let computedPk := wotsChainVerify sigOffset sigLen message seed

    -- Compare reconstructed PK with stored PK
    require (computedPk == pkHashClean) "Invalid signature"

    -- Mark used: set bit 0 of pkHash
    setStorage pkHashSlot (bitOr pkHashRaw 1)

    return 1

  /-- Check if the key has been used. -/
  function isUsed () : Uint256 := do
    let pkHashRaw ← getStorage pkHashSlot
    return (bitAnd pkHashRaw 1)

  /-- Read the pkSeed. -/
  function getPkSeed () : Uint256 := do
    let seed ← getStorage pkSeedSlot
    return seed

end Contracts
