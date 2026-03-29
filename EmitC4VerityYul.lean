import Compiler.ABI
import Compiler.Codegen
import Compiler.CompilationModel.LayoutReport
import Compiler.CompilationModel.TrustSurface
import Compiler.Selector
import Compiler.Yul.PrettyPrint
import Sphincs.C4.Frontier

open Compiler
open Compiler.CompilationModel

private def outDir : System.FilePath := "proof-artifacts" / "c4-verity"

private def ensureDir (path : System.FilePath) : IO Unit :=
  IO.FS.createDirAll path

unsafe def main (_args : List String) : IO Unit := do
  let spec := Sphincs.C4.Frontier.spec
  let selectors ← Selector.computeSelectors spec
  let ir ←
    match CompilationModel.compile spec selectors with
    | .ok ir => pure ir
    | .error err => throw <| IO.userError s!"Failed to compile C4 Verity frontier: {err}"

  let options : YulEmitOptions := {
    backendProfile := .semantic
    patchConfig := { enabled := true, maxIterations := 2 }
  }
  let (yulObj, patchReport) := emitYulWithOptionsReport ir options
  let rendered := Yul.render yulObj

  ensureDir outDir
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.yul") rendered
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.abi.json") (Compiler.ABI.emitContractABIJson spec)
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.trust.json") (emitTrustReportJson [spec] ++ "\n")
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.assumptions.json") (emitAssumptionReportJson [spec] ++ "\n")
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.layout.json") (emitLayoutReportJson [spec] ++ "\n")
  IO.FS.writeFile (outDir / "SphincsC4VerifierFrontier.patch.txt") (reprStr patchReport ++ "\n")
  IO.println s!"Wrote C4 Verity frontier artifacts to {outDir}"
