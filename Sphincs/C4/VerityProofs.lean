import Sphincs.C4.Frontier

namespace Sphincs.C4.VerityProofs

open Compiler.CompilationModel
open Sphincs.C4.Circuit
open Sphincs.C4.Frontier

theorem field_count : fields.length = 2 := rfl

theorem field_slots :
    fields.map (fun f => (f.name, f.slot)) = [("pkSeed", some 0), ("pkRoot", some 1)] := rfl

theorem constructor_params_shape :
    constructorSpec.params.map (fun p => (p.name, p.ty)) =
      [("seed", .bytes32), ("root", .bytes32)] := rfl

theorem constructor_body_writes_seed_root :
    constructorSpec.body =
      [ .setStorage "pkSeed" (.param "seed")
      , .setStorage "pkRoot" (.param "root")
      ] := rfl

theorem verify_local_obligation_count :
    verifySpec.localObligations.length = 3 := rfl

theorem verify_signature_shape :
    verifySpec.params.map (fun p => (p.name, p.ty)) =
      [("message", .bytes32), ("sig", .bytes)] := rfl

theorem verify_returns_bool :
    verifySpec.returns = [.bool] := rfl

theorem verify_body_has_length_guard :
    verifyBody.take 5 =
      [ .letVar "sigLenAnchor" (.literal SigLenCalldataOffset)
      , .letVar "sigBaseAnchor" (.literal SigBytesCalldataBase)
      , .letVar "inputLen" (.literal HMsgInputLen)
      , .letVar "sigLen" (.calldataload (.literal 68))
      , .require (.eq (.localVar "sigLen") (.literal SigSize)) "Invalid sig length"
      ] := by
  simp [verifyBody]

theorem verify_body_has_top_hash_skeleton :
    verifyBody.reverse.take 3 =
      [ .returnValues [(.literal 1)]
      , .letVar "htIdx" (.bitAnd (.shr (.literal 112) (.localVar "digest")) (.literal HtIdxMask))
      , .letVar "digest" (.keccak256 (.literal 0) (.literal HMsgInputLen))
      ] := by
  simp [verifyBody]

theorem spec_names_contract :
    spec.name = "SphincsC4VerifierFrontier" := rfl

end Sphincs.C4.VerityProofs
