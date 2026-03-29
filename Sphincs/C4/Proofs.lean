import Sphincs.C4.Circuit

namespace Sphincs.C4.Proofs

open Sphincs.C4.Circuit

theorem auth_start_eq : AuthStart = 144 := by native_decide
theorem ht_start_eq : HtStart = 1712 := by native_decide
theorem layer_size_eq : LayerSize = 676 := by native_decide
theorem sig_size_eq : SigSize = 3740 := by native_decide

theorem layer0_offset_eq : layerOffset 0 = 1712 := by native_decide
theorem layer1_offset_eq : layerOffset 1 = 2388 := by native_decide
theorem layer2_offset_eq : layerOffset 2 = 3064 := by native_decide

theorem layer0_end_eq : layerEnd 0 = 2388 := by native_decide
theorem layer1_end_eq : layerEnd 1 = 3064 := by native_decide
theorem layer2_end_eq : layerEnd 2 = SigSize := by native_decide

theorem count_offset_eq (layer : Nat) :
    countOffset layer = layerOffset layer + 512 := by
  simp [countOffset, layerOffset, L, N]

theorem auth_offset_eq (layer : Nat) :
    authOffset layer = layerOffset layer + 516 := by
  simp [authOffset, countOffset, layerOffset, L, N]

theorem extractBits_lt (word offset width : Nat) :
    extractBits word offset width < 2 ^ width := by
  unfold extractBits
  have hpow : 0 < 2 ^ width := by
    induction width with
    | zero =>
        simp
    | succ n ih =>
        simpa [Nat.pow_succ, Nat.mul_comm] using Nat.mul_pos ih (by decide : 0 < 2)
  exact Nat.mod_lt _ hpow

theorem extractHtIdx_lt (digest : Nat) :
    extractHtIdx digest < 2 ^ H := by
  simpa [extractHtIdx] using extractBits_lt digest 112 H

theorem extractForsIndex_lt (digest tree : Nat) :
    extractForsIndex digest tree < 2 ^ A := by
  simpa [extractForsIndex] using extractBits_lt digest (tree * A) A

theorem parse_wrong_length_returns_none (sig : ByteArray) (h : sig.size ≠ SigSize) :
    parse? sig = none := by
  simp [parse?, h]

theorem parse_correct_length_returns_some (sig : ByteArray) (h : sig.size = SigSize) :
    (parse? sig).isSome = true := by
  simp [parse?, h]

end Sphincs.C4.Proofs
