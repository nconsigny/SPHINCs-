# C4 Verity Frontier

This worktree contains a focused Verity package for the C4 verifier family:

- Solidity target: `src/SphincsWcFc30.sol`
- Assembly target: `src/SphincsWcFc30Asm.sol`
- Parameter set: `h=30, d=3, k=8, a=14, w=16`
- Signature size: `3740` bytes

## What is proved now

- the fixed C4 signature byte layout and offsets
- bounded extraction facts for the digest-derived hypertree and FORS indices
- the constructor storage binding for `pkSeed` and `pkRoot`
- the frontier shape of `verify(bytes32,bytes)`:
  - calldata length anchor
  - signature-length guard
  - top-hash framing skeleton
  - boolean return shape

## What is not yet proved

- full FORS+C loop equivalence to `src/SphincsWcFc30Asm.sol`
- full WOTS+C chain completion equivalence
- full hypertree authentication loop equivalence
- end-to-end cryptographic security reduction over the concrete circuit

## Trust surface

The current frontier model keeps three explicit local obligations:

1. calldata layout for `verify(bytes32,bytes)`
2. top-hash framing equivalence (`seed || root || R || message`)
3. the remaining FORS+C / WOTS+C / hypertree loop refinement

This is an M2/M3 checkpoint: the byte layout and verifier boundary are formalized, and the Verity/Yul rewrite is executable, but it is not yet a full bytecode equivalence proof.
