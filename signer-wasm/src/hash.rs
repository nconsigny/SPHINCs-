//! Keccak256-based tweakable hash primitives matching TweakableHash.sol.

use tiny_keccak::{Hasher, Keccak};

/// N_MASK: keep only top 128 bits of a 256-bit value.
const N_MASK_HI: u64 = u64::MAX;
const N_MASK_LO: u64 = u64::MAX;

pub type U256 = [u64; 4]; // big-endian word order: [0] = MSW

pub const ZERO: U256 = [0; 4];

pub fn to_bytes32(val: U256) -> [u8; 32] {
    crate::u256_to_be(&val)
}

pub fn from_bytes32(b: &[u8; 32]) -> U256 {
    crate::u256_from_be(b)
}

/// Apply N_MASK: keep top 128 bits, zero bottom 128 bits.
#[inline(always)]
pub fn mask_n(val: U256) -> U256 {
    [val[0] & N_MASK_HI, val[1] & N_MASK_LO, 0, 0]
}

/// keccak256 of arbitrary bytes → U256
pub fn keccak256(data: &[u8]) -> U256 {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    from_bytes32(&out)
}

/// keccak256(a || b || c) — 96 bytes, hot path for chain hashing
#[inline(always)]
pub fn keccak_3x32(a: U256, b: U256, c: U256) -> U256 {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(&to_bytes32(a));
    buf[32..64].copy_from_slice(&to_bytes32(b));
    buf[64..96].copy_from_slice(&to_bytes32(c));
    keccak256(&buf)
}

/// keccak256(a || b || c || d) — 128 bytes
#[inline(always)]
pub fn keccak_4x32(a: U256, b: U256, c: U256, d: U256) -> U256 {
    let mut buf = [0u8; 128];
    buf[0..32].copy_from_slice(&to_bytes32(a));
    buf[32..64].copy_from_slice(&to_bytes32(b));
    buf[64..96].copy_from_slice(&to_bytes32(c));
    buf[96..128].copy_from_slice(&to_bytes32(d));
    keccak256(&buf)
}

// ===== Tweakable Hash Primitives =====

/// ADRS: pack (layer, tree, type, kp, chain_idx, chain_pos, hash_addr) into U256.
pub fn make_adrs(layer: u32, tree: u64, atype: u32, kp: u32, ci: u32, cp: u32, ha: u32) -> U256 {
    let w0 = ((layer as u64) << 32) | ((tree >> 32) & 0xFFFFFFFF);
    let w1 = ((tree & 0xFFFFFFFF) << 32) | (atype as u64);
    let w2 = ((kp as u64) << 32) | (ci as u64);
    let w3 = ((cp as u64) << 32) | (ha as u64);
    [w0, w1, w2, w3]
}

/// Th(seed, adrs, input) → 128-bit (masked)
#[inline(always)]
pub fn th(seed: U256, adrs: U256, input: U256) -> U256 {
    mask_n(keccak_3x32(seed, adrs, input))
}

/// ThPair(seed, adrs, left, right) → 128-bit (masked)
#[inline(always)]
pub fn th_pair(seed: U256, adrs: U256, left: U256, right: U256) -> U256 {
    mask_n(keccak_4x32(seed, adrs, left, right))
}

/// ThMulti(seed, adrs, values...) → 128-bit (masked)
pub fn th_multi(seed: U256, adrs: U256, values: &[U256]) -> U256 {
    let mut data = Vec::with_capacity(64 + values.len() * 32);
    data.extend_from_slice(&to_bytes32(seed));
    data.extend_from_slice(&to_bytes32(adrs));
    for v in values {
        data.extend_from_slice(&to_bytes32(*v));
    }
    mask_n(keccak256(&data))
}

/// H_msg(seed, root, R, message) → full 256-bit digest
pub fn h_msg(seed: U256, root: U256, r: U256, message: U256) -> U256 {
    keccak_4x32(seed, root, r, message)
}

/// Chain hash: iterate th from start_pos for `steps` applications.
pub fn chain_hash(seed: U256, adrs: U256, mut val: U256, start_pos: u32, steps: u32) -> U256 {
    let mut a = adrs;
    for step in 0..steps {
        let pos = start_pos + step;
        // Set chain_pos (bytes 24-27) in ADRS
        a[3] = ((pos as u64) << 32) | (a[3] & 0xFFFFFFFF);
        val = mask_n(keccak_3x32(seed, a, val));
    }
    val
}

/// Set chain index in ADRS word 2 (bytes 20-23).
pub fn set_chain_index(adrs: U256, idx: u32) -> U256 {
    let mut a = adrs;
    a[2] = (a[2] & 0xFFFFFFFF_00000000) | (idx as u64);
    a
}

/// Extract a u32 from U256 bytes at a given position.
pub fn u256_shr(val: &U256, bits: usize) -> u64 {
    // Reconstruct as big integer shift
    let total_bits = 256;
    if bits >= total_bits { return 0; }
    let word_idx = bits / 64;
    let bit_idx = bits % 64;
    // Words are in big-endian order: val[0] is bits 255..192
    let be_word_idx = 3 - word_idx;
    if bit_idx == 0 {
        val[be_word_idx]
    } else if be_word_idx == 0 {
        val[0] >> bit_idx
    } else {
        (val[be_word_idx] >> bit_idx) | (val[be_word_idx - 1] << (64 - bit_idx))
    }
}

/// Convert u32 to U256 (in big-endian position, value in least significant word).
pub fn u256_from_u32(val: u32) -> U256 {
    [0, 0, 0, val as u64]
}
