# Verity Architecture for SPHINCS-

This directory now distinguishes two very different things:

- `SphincsC6/`: an exploratory Lean model of the current SPHINCS- C6 verifier.
- `SphincsKernel/`: the recommended Verity architecture, intentionally small and fully replayable.

## Why this change

The previous `SphincsC6Full/` and `SphincsC6V/` trees tried to make a very large SPHINCS verifier look "fully verified" inside Verity, but the important correctness argument was either absent, vacuous, or pushed behind local assumptions. That is not the right way to use Verity if the goal is to claim strong guarantees.

The right use of Verity here is to verify a tiny contract kernel whose behavior is:

1. easy to specify,
2. easy to audit,
3. easy to replay in CI,
4. compiled through Verity with no local obligations and no axiomatized primitives.

## Recommended kernel

`SphincsKernel/` is that kernel.

It stores an expected root and exposes two pure operations:

- `previewPath`: reconstruct a fixed-depth Merkle root from a leaf plus four auth nodes.
- `verifyPath`: accept iff the reconstructed root equals the stored root.

The model is deliberately tiny:

- `Model.lean` defines the mathematical kernel.
- `MerkleKernel.lean` defines the Verity contract.
- `Spec.lean` defines the exact contract specs.
- `Examples.lean` contains concrete sample scenarios for local exploration.

## What is actually guaranteed

For `SphincsKernel/`, the guarantee is exact and simple:

- the EVM contract computes the same root as the Lean model;
- `verifyPath = true` iff the reconstructed root equals the stored root;
- `verifyPath` is read-only;
- there are no `sorry`;
- there are no local unsafe/refinement obligations;
- there are no axiomatized primitives such as `keccak256`.

This is the kind of statement Verity is well-suited to make today.

## What this means for SPHINCS-

For the full SPHINCS- verifier, the better architecture is:

1. keep the heavy cryptographic construction as a pure reference model and test oracle;
2. isolate the smallest on-chain acceptance kernel;
3. verify that kernel end-to-end with Verity;
4. only claim the guarantees that the verified kernel really provides.

In practice, that means Verity should own the boundary that decides acceptance from a compact, typed witness, not a giant handwritten reimplementation of every SPHINCS subroutine with informal proof gaps.

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

## EVM replay test

The Yul artifact is not just generated; it is exercised directly in Foundry.

```bash
# From the repo root
forge test --match-contract MerkleKernelVerityTest -vv
```

That test:

- recompiles `verity/artifacts/sphincs-kernel/MerkleKernel.yul` into deployable bytecode,
- deploys the raw Verity artifact,
- checks named example vectors,
- fuzzes `previewPath` against a tiny Solidity reference model,
- fuzzes `verifyPath` to show acceptance iff `candidateRoot == storedRoot`,
- checks that verification preserves storage.

## Narrative value

This kernel is intentionally modest, but the value is obvious:

- the acceptance rule is small enough to understand in one sitting;
- the spec matches the implementation exactly;
- the compiled contract inherits Verity's compilation guarantees;
- the repo stops overstating what is and is not formally proved.
