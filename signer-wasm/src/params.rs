//! C6 parameter constants: W+C_F+C h=24 d=2 a=16 k=8 w=16

pub const N: usize = 16; // hash output bytes (128 bits)
pub const H: usize = 24;
pub const D: usize = 2;
pub const SUBTREE_H: usize = 12; // H / D
pub const A: usize = 16;
pub const K: usize = 8;
pub const W: usize = 16;
pub const LOG_W: usize = 4;
pub const L: usize = 32; // 128 / LOG_W
pub const TARGET_SUM: usize = 240; // (W-1)*L/2
pub const W_MASK: u64 = 0xF;

// Signature layout (R=N=16)
pub const FORS_START: usize = N;
pub const AUTH_START: usize = N + K * N; // 16 + 128 = 144
pub const HT_START: usize = AUTH_START + (K - 1) * A * N; // 144 + 1792 = 1936
pub const LAYER_SIZE: usize = L * N + 4 + SUBTREE_H * N; // 512 + 4 + 192 = 708
pub const SIG_SIZE: usize = HT_START + D * LAYER_SIZE; // 1936 + 1416 = 3352

// BIP-44 derivation path for Ethereum
pub const BIP44_PATH: &str = "m/44'/60'/0'/0/0";
