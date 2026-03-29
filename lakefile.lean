import Lake
open Lake DSL

package «sphincs-verity-proofs» where
  version := v!"0.1.0"

require verity from "../verity-ref"

@[default_target]
lean_lib «Sphincs» where
  globs := #[
    .one `Sphincs,
    .andSubmodules `Sphincs
  ]

lean_exe «emit-c4-verity-yul» where
  root := `EmitC4VerityYul
