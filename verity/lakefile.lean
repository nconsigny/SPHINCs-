import Lake
open Lake DSL

package SphincsC6Verity where
  leanOptions := #[⟨`autoImplicit, false⟩]

require verity from "../../verity-framework"

lean_lib SphincsC6 where
  srcDir := "SphincsC6"
  roots := #[`Types, `Hash, `WotsC, `ForsC, `Hypertree, `Contract, `Spec]

lean_lib Proofs where
  srcDir := "SphincsC6/Proofs"
  roots := #[`Correctness]

lean_lib SphincsKernel where
  srcDir := "."
  roots := #[`SphincsKernel.Model, `SphincsKernel.MerkleKernel, `SphincsKernel.Spec,
    `SphincsKernel.Examples, `SphincsKernel.Proofs.Basic, `SphincsKernel.Proofs.Correctness]
