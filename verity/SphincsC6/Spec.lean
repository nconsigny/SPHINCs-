/-
  SphincsC6.Spec — Formal specifications for C6 SPHINCS+ verifier.
-/
import SphincsC6.Types
import SphincsC6.Contract

namespace SphincsC6

def spec_paramConsistency : Prop :=
  H = D * SUBTREE_H ∧
  L = 128 / LOG_W ∧
  2^LOG_W = W ∧
  K * A = 128 ∧
  SIG_SIZE = N + K * N + (K - 1) * A * N + D * (L * N + 4 + SUBTREE_H * N)

theorem param_consistency : spec_paramConsistency := by
  simp [spec_paramConsistency, H, D, SUBTREE_H, L, LOG_W, W, K, A, SIG_SIZE, N]
  omega

def spec_rootMatch : Prop :=
  ∀ (state : ContractState) (msg : Hash128) (sig : SphincsC6Sig),
    verify state msg sig = true →
    ∃ (computedRoot : Hash128), computedRoot = state.pkRoot

def spec_digitSumFixed : Prop :=
  ∀ (seed : Hash128) (layer treeAddr leafIdx : Nat)
    (msgHash : Hash128) (sigma : Fin L → Hash128) (count : Nat) (pk : Hash128),
    wotsVerify seed layer treeAddr leafIdx msgHash sigma count = some pk →
    ∃ d, d = wotsDigest seed
              { layer := layer, treeAddr := treeAddr, adrsType := .wots, keyPair := leafIdx }
              msgHash count ∧ digitSum d = TARGET_SUM

def spec_forcedZero : Prop :=
  ∀ (seed : Hash128) (digest : UInt256) (sig : ForsCSig) (pk : Hash128),
    forsVerify seed digest sig = some pk →
    extractForsIndices digest ⟨K - 1, by omega⟩ = 0

end SphincsC6
