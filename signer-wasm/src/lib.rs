//! SPHINCS+ C6 WASM signer with post-quantum-safe BIP-39 key derivation.
//!
//! SPHINCS+ keys are derived directly from the BIP-39 seed via HMAC-SHA512,
//! bypassing ECDSA. The ECDSA address is derived independently for account ID.
//!
//! C6: W+C_F+C h=24, d=2, a=16, k=8, w=16, l=32, target_sum=240

pub mod hash;
pub mod params;
pub mod keygen;
pub mod wots;
pub mod fors;
pub mod merkle;
pub mod sphincs;

use wasm_bindgen::prelude::*;

/// Generate SPHINCS+ keypair from a BIP-39 mnemonic.
/// Returns JSON: { "seed": "0x...", "root": "0x...", "ecdsa_address": "0x..." }
#[wasm_bindgen]
pub fn keygen_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    let (seed, _sk_seed, root, ecdsa_addr) = keygen::from_mnemonic(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e))?;
    let result = serde_json::json!({
        "seed": format!("0x{}", hex::encode(hash::to_bytes32(seed))),
        "root": format!("0x{}", hex::encode(hash::to_bytes32(root))),
        "ecdsa_address": ecdsa_addr,
    });
    Ok(result.to_string())
}

/// Sign a message hash (32 bytes hex) using a BIP-39 mnemonic.
/// Returns the raw signature as hex (3352 bytes).
#[wasm_bindgen]
pub fn sign_from_mnemonic(mnemonic: &str, passphrase: &str, message_hex: &str) -> Result<String, JsValue> {
    let (seed, sk_seed, root, _) = keygen::from_mnemonic(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e))?;

    let msg_bytes = hex::decode(message_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&format!("bad hex: {e}")))?;
    if msg_bytes.len() != 32 {
        return Err(JsValue::from_str("message must be 32 bytes"));
    }
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&msg_bytes);
    let message = u256_from_be(&msg);

    let sig = sphincs::sign(seed, sk_seed, root, message)
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(format!("0x{}", hex::encode(&sig)))
}

/// Sign with a pre-derived keypair (hex seed, hex sk_seed, hex root, hex message).
/// Skips BIP-39 derivation and pkRoot rebuild — fastest path.
#[wasm_bindgen]
pub fn sign_with_keys(seed_hex: &str, sk_seed_hex: &str, root_hex: &str, message_hex: &str) -> Result<String, JsValue> {
    let seed = parse_u256(seed_hex)?;
    let sk_seed = parse_u256(sk_seed_hex)?;
    let root = parse_u256(root_hex)?;
    let message = parse_u256(message_hex)?;

    let sig = sphincs::sign(seed, sk_seed, root, message)
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(format!("0x{}", hex::encode(&sig)))
}

fn parse_u256(hex_str: &str) -> Result<[u64; 4], JsValue> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&format!("bad hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("expected 32 bytes"));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(u256_from_be(&buf))
}

/// Convert 32 big-endian bytes to [u64; 4] (big-endian word order: [0] = most significant)
pub fn u256_from_be(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

pub fn u256_to_be(val: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&val[0].to_be_bytes());
    out[8..16].copy_from_slice(&val[1].to_be_bytes());
    out[16..24].copy_from_slice(&val[2].to_be_bytes());
    out[24..32].copy_from_slice(&val[3].to_be_bytes());
    out
}
