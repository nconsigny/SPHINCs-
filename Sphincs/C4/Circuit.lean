namespace Sphincs.C4.Circuit

/-- Core byte/height parameters for contract C4 (`h=30, d=3, k=8, a=14`). -/
def N : Nat := 16
def H : Nat := 30
def D : Nat := 3
def SubtreeH : Nat := 10
def A : Nat := 14
def K : Nat := 8
def W : Nat := 16
def L : Nat := 32

/-- Fixed byte layout from `src/SphincsWcFc30Asm.sol`. -/
def ForsStart : Nat := N
def AuthStart : Nat := N + K * N
def HtStart : Nat := AuthStart + (K - 1) * A * N
def LayerSize : Nat := L * N + 4 + SubtreeH * N
def SigSize : Nat := HtStart + D * LayerSize

def SigLenCalldataOffset : Nat := 0x44
def SigBytesCalldataBase : Nat := 0x64
def HMsgInputLen : Nat := 0x80

def ForsForcedZeroIndex : Nat := K - 1
def ForsForcedZeroShift : Nat := ForsForcedZeroIndex * A

def NMask : Nat :=
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

def HtIdxMask : Nat := (2 ^ H) - 1

def layerOffset (layer : Nat) : Nat :=
  HtStart + layer * LayerSize

def layerEnd (layer : Nat) : Nat :=
  layerOffset layer + LayerSize

def sigmaOffset (layer : Nat) : Nat :=
  layerOffset layer

def countOffset (layer : Nat) : Nat :=
  layerOffset layer + L * N

def authOffset (layer : Nat) : Nat :=
  countOffset layer + 4

def extractBits (word offset width : Nat) : Nat :=
  (word / 2 ^ offset) % 2 ^ width

def extractHtIdx (digest : Nat) : Nat :=
  extractBits digest 112 H

def extractForsIndex (digest tree : Nat) : Nat :=
  extractBits digest (tree * A) A

structure LayerView where
  sigmaBlock : ByteArray
  countBlock : ByteArray
  authBlock : ByteArray
  deriving DecidableEq

structure ParsedSignature where
  randomness : ByteArray
  forsSecretBlock : ByteArray
  forsAuthBlock : ByteArray
  layer0 : LayerView
  layer1 : LayerView
  layer2 : LayerView
  deriving DecidableEq

def parseLayer (sig : ByteArray) (layer : Nat) : LayerView :=
  { sigmaBlock := sig.extract (sigmaOffset layer) (countOffset layer)
    countBlock := sig.extract (countOffset layer) (authOffset layer)
    authBlock := sig.extract (authOffset layer) (layerEnd layer) }

def parse? (sig : ByteArray) : Option ParsedSignature :=
  if sig.size = SigSize then
    some {
      randomness := sig.extract 0 N
      forsSecretBlock := sig.extract ForsStart AuthStart
      forsAuthBlock := sig.extract AuthStart HtStart
      layer0 := parseLayer sig 0
      layer1 := parseLayer sig 1
      layer2 := parseLayer sig 2
    }
  else
    none

end Sphincs.C4.Circuit
