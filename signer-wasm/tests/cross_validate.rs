//! Cross-validation: Rust signer must produce identical outputs to Python signer.

use sphincs_c6_signer::hash;
use sphincs_c6_signer::wots;
use sphincs_c6_signer::fors;
use sphincs_c6_signer::merkle;
use sphincs_c6_signer::sphincs;

fn hex_to_u256(hex: &str) -> hash::U256 {
    let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    sphincs_c6_signer::u256_from_be(&buf)
}

fn u256_hex(val: &hash::U256) -> String {
    format!("0x{}", hex::encode(hash::to_bytes32(*val)))
}

/// Reference values from Python signer with test_entropy = [0x42] * 32
const PY_PK_SEED: &str = "0x012dd57311a3728fd6988fb2a583bb9e00000000000000000000000000000000";
const PY_SK_SEED: &str = "0x11d47d1635d4ad4852852dae8fd9dbbd699558d7907907cdae4203bdbae7f7aa";
const PY_PK_ROOT: &str = "0xd937b687fe8c5a0d329b30a2cb88705b00000000000000000000000000000000";
const PY_WOTS_SK_1_0_0_0: &str = "0x60fd5cf59c3c018fca334b8538cc52fe00000000000000000000000000000000";
const PY_WOTS_DIGEST_0: &str = "0x7de15fe836b255f1dc2981f0f7cba89f1e0df041c23e6e9dd669a144845474be";
const PY_FORS_SECRET_0_0: &str = "0x644806f57db3ea90131947530251a86200000000000000000000000000000000";

fn derive_test_keys() -> (hash::U256, hash::U256) {
    let test_entropy = [0x42u8; 32];
    let pk_seed = hash::mask_n(hash::keccak256(&[b"pk_seed".as_slice(), &test_entropy].concat()));
    let sk_seed = hash::keccak256(&[b"sk_seed".as_slice(), &test_entropy].concat());
    (pk_seed, sk_seed)
}

#[test]
fn test_key_derivation_matches_python() {
    let (pk_seed, sk_seed) = derive_test_keys();
    assert_eq!(u256_hex(&pk_seed), PY_PK_SEED, "pk_seed mismatch");
    assert_eq!(u256_hex(&sk_seed), PY_SK_SEED, "sk_seed mismatch");
}

#[test]
fn test_wots_secret_matches_python() {
    let (_, sk_seed) = derive_test_keys();
    let sk0 = wots::wots_secret(sk_seed, 1, 0, 0, 0);
    assert_eq!(u256_hex(&sk0), PY_WOTS_SK_1_0_0_0, "wots_secret(1,0,0,0) mismatch");
}

#[test]
fn test_wots_digest_matches_python() {
    let (pk_seed, _) = derive_test_keys();
    let pk_root = hex_to_u256(PY_PK_ROOT);
    let d = wots::wots_digest(pk_seed, 1, 0, 0, pk_root, 0);
    assert_eq!(u256_hex(&d), PY_WOTS_DIGEST_0, "wots_digest(count=0) mismatch");
}

#[test]
fn test_fors_secret_matches_python() {
    let (_, sk_seed) = derive_test_keys();
    let fs = fors::fors_secret(sk_seed, 0, 0);
    assert_eq!(u256_hex(&fs), PY_FORS_SECRET_0_0, "fors_secret(0,0) mismatch");
}

#[test]
#[ignore] // ~3s in release mode
fn test_pkroot_matches_python() {
    let (pk_seed, sk_seed) = derive_test_keys();
    let pk_root = merkle::build_subtree_root(pk_seed, sk_seed, 1, 0);
    assert_eq!(u256_hex(&pk_root), PY_PK_ROOT, "pkRoot mismatch — Rust and Python produce different trees");
}

#[test]
#[ignore] // ~3s in release mode
fn test_full_sign_produces_valid_sig() {
    let (pk_seed, sk_seed) = derive_test_keys();
    let pk_root = merkle::build_subtree_root(pk_seed, sk_seed, 1, 0);
    assert_eq!(u256_hex(&pk_root), PY_PK_ROOT);

    let message = hash::keccak256(b"test message for C6");
    let sig = sphincs::sign(pk_seed, sk_seed, pk_root, message)
        .expect("signing failed");
    assert_eq!(sig.len(), 3352, "sig size");

    // R should be non-zero
    assert!(sig[0..16].iter().any(|&b| b != 0), "R is zero");
}

#[test]
fn test_keccak256_empty() {
    let hash = hash::keccak256(b"");
    assert_eq!(
        u256_hex(&hash),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn test_params() {
    assert_eq!(sphincs_c6_signer::params::SIG_SIZE, 3352);
    assert_eq!(sphincs_c6_signer::params::H, 24);
    assert_eq!(sphincs_c6_signer::params::SUBTREE_H, 12);
    assert_eq!(sphincs_c6_signer::params::K * sphincs_c6_signer::params::A, 128);
}
