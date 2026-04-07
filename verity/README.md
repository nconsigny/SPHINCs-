# Formally Checked Merkle Acceptance Kernel

This directory contains a small Verity artifact for SPHINCS-style witnesses.

The public claim is narrow and strong:

- a typed witness reconstructs exactly one root,
- `verifyPath` returns `true` iff that reconstructed root equals the stored root,
- `verifyPackedPath` returns `true` iff the packed input is canonical, decodes to that typed witness, and the reconstructed root equals the stored root,
- both verification entrypoints are read-only.

Malformed packed encodings fail in one simple, explicit way: any direction word with non-zero bits above the low 4 bits is rejected.

This kernel does not prove full SPHINCS cryptography or the production C6 verifier. It proves the on-chain Merkle acceptance boundary.

## Proof Boundary

The verified artifact is [`SphincsKernel/`](./SphincsKernel/).

It stores one expected root and exposes two read-only acceptance APIs:

- `verifyPath`: takes a fully decoded witness with 4 explicit direction booleans.
- `verifyPackedPath`: takes the same witness with the directions packed into the low 4 bits of one word, and rejects non-canonical encodings.

Exact on-chain guarantee:

- `previewPath` and `previewPackedPath` reconstruct exactly the root defined by the Lean model.
- `verifyPath` returns `true` if and only if the reconstructed root equals the stored root.
- `verifyPackedPath` returns `true` if and only if the packed input is canonical and the decoded witness reconstructs the stored root.
- Both verification entrypoints preserve storage.
- The contract is compiled with `--deny-local-obligations` and `--deny-axiomatized-primitives`.

Outside the proof boundary:

- the toy `compress` function is not claimed to be cryptographically secure,
- the full `SphincsC6/` verifier is not claimed here,
- witness derivation, signature parsing, and integration logic live outside this verified kernel.

What is proved:

- Lean proves the acceptance rule.
- Verity proves the compiled EVM contract implements that rule.

## File map

- `SphincsKernel/Model.lean`: typed witness model, packed witness decoding, and acceptance rule.
- `SphincsKernel/MerkleKernel.lean`: Verity contract that calls the shared Lean model directly.
- `SphincsKernel/Spec.lean`: exact function-level specs.
- `SphincsKernel/Proofs/Correctness.lean`: user-facing theorems such as acceptance iff reconstructed root matches storage.
- `SphincsKernel/Examples.lean`: named examples for a concrete witness.

## Main properties

The core statements are:

- A witness is accepted exactly when it reconstructs the configured root.
- A packed witness is accepted exactly when its encoding is canonical and its decoded witness reconstructs the configured root.
- Verification is read-only.
- If you configure the contract with the root reconstructed from a witness, that witness will verify.

That gives a small, inspectable, replayable kernel with one sharp claim instead of a broader but blurrier SPHINCS story.

## Build and strict checks

```bash
cd verity
lake update
lake build

# Strict Verity compilation of the recommended kernel
lake exe verity-compiler \
  --module SphincsKernel.MerkleKernel \
  --deny-local-obligations \
  --deny-axiomatized-primitives \
  --output artifacts/sphincs-kernel
```

## EVM replay tests

The Yul artifact is not just generated; it is exercised directly in Foundry.

```bash
# From the repo root
forge test --match-contract MerkleKernelVerityTest -vv
```

That test:

- recompiles `verity/artifacts/sphincs-kernel/MerkleKernel.yul` into deployable bytecode,
- deploys the raw Verity artifact,
- checks named example vectors for both explicit and packed witnesses,
- fuzzes `previewPath` against a tiny Solidity reference model,
- fuzzes `previewPackedPath` against a reference packed-decoding model,
- fuzzes `verifyPath` to show acceptance iff `candidateRoot == storedRoot`,
- fuzzes `verifyPackedPath` to show acceptance iff the decoded witness matches the stored root,
- checks that verification preserves storage.

## Why this is useful for SPHINCS-

For a real SPHINCS deployment, this suggests the better split:

1. Parse and derive a typed witness outside the verified core.
2. Keep the heavy cryptographic logic as a reference model and test oracle.
3. Hand only the Merkle acceptance step to the verified kernel.
4. State guarantees exactly at that boundary, not beyond it.

That gives users something they can actually reason about: what exact witness shape is accepted on-chain, and what exact property the contract enforces.
