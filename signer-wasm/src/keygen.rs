//! BIP-39/44 → SPHINCS+ C6 key derivation.
//!
//! Flow: mnemonic → BIP-39 seed → BIP-32 at m/44'/60'/0'/0/0 → ECDSA privkey
//!       → SPHINCS+ (pkSeed, skSeed, pkRoot)

use crate::hash::{self, U256};
use crate::merkle;
use crate::params::*;

use hmac::{Hmac, Mac};
use sha2::Sha512;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

type HmacSha512 = Hmac<Sha512>;

/// Derive SPHINCS+ keypair from BIP-39 mnemonic.
/// Returns (pkSeed, skSeed, pkRoot, ecdsa_address_hex).
pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<(U256, U256, U256, String), String> {
    // Step 1: BIP-39 mnemonic → 512-bit seed
    let m: bip39::Mnemonic = mnemonic.parse().map_err(|e| format!("invalid mnemonic: {e}"))?;
    let bip39_seed = m.to_seed_normalized(passphrase);

    // Step 2: BIP-32 derive at m/44'/60'/0'/0/0
    let ecdsa_key = derive_bip32(&bip39_seed, &[
        0x8000002C, // 44'
        0x8000003C, // 60'
        0x80000000, // 0'
        0,          // 0
        0,          // 0
    ])?;

    // Step 3: Compute ECDSA address
    let signing_key = SigningKey::from_bytes((&ecdsa_key).into())
        .map_err(|e| format!("invalid key: {e}"))?;
    let pubkey = signing_key.verifying_key();
    let encoded = pubkey.to_encoded_point(false);
    let pubkey_bytes = &encoded.as_bytes()[1..]; // skip 0x04 prefix
    let addr_hash = hash::keccak256(pubkey_bytes);
    let addr_bytes = hash::to_bytes32(addr_hash);
    let ecdsa_address = format!("0x{}", hex::encode(&addr_bytes[12..32]));

    // Step 4: SPHINCS+ key derivation (matches signer.py derive_keys)
    let entropy = hash::keccak256(&[
        b"sphincs_signer_v1".as_slice(),
        &ecdsa_key,
    ].concat());
    let pk_seed = hash::mask_n(hash::keccak256(&[
        b"pk_seed".as_slice(),
        &hash::to_bytes32(entropy),
    ].concat()));
    let sk_seed = hash::keccak256(&[
        b"sk_seed".as_slice(),
        &hash::to_bytes32(entropy),
    ].concat());

    // Step 5: Build pkRoot (top-layer subtree)
    let pk_root = merkle::build_subtree_root(pk_seed, sk_seed, 1, 0);

    Ok((pk_seed, sk_seed, pk_root, ecdsa_address))
}

/// Derive from raw ECDSA private key bytes (32 bytes hex).
pub fn from_private_key(privkey_hex: &str) -> Result<(U256, U256, U256), String> {
    let key_bytes = hex::decode(privkey_hex.trim_start_matches("0x"))
        .map_err(|e| format!("bad hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err("private key must be 32 bytes".into());
    }

    // Same derivation as signer.py
    let entropy_input = [&key_bytes[..], b"c6"].concat();
    let keygen_msg = hash::keccak256(&[b"sphincs_keygen".as_slice(), &entropy_input].concat());

    let entropy = hash::keccak256(&[
        b"sphincs_signer_v1".as_slice(),
        &hash::to_bytes32(keygen_msg),
    ].concat());
    let pk_seed = hash::mask_n(hash::keccak256(&[
        b"pk_seed".as_slice(),
        &hash::to_bytes32(entropy),
    ].concat()));
    let sk_seed = hash::keccak256(&[
        b"sk_seed".as_slice(),
        &hash::to_bytes32(entropy),
    ].concat());

    let pk_root = merkle::build_subtree_root(pk_seed, sk_seed, 1, 0);

    Ok((pk_seed, sk_seed, pk_root))
}

/// BIP-32 key derivation (hardened and non-hardened).
fn derive_bip32(seed: &[u8], path: &[u32]) -> Result<[u8; 32], String> {
    // Master key from seed
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|_| "HMAC init failed")?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[0..32]);
    chain_code.copy_from_slice(&result[32..64]);

    // Derive each level
    for &child in path {
        let hardened = child & 0x80000000 != 0;
        let mut data = Vec::with_capacity(37);

        if hardened {
            data.push(0x00);
            data.extend_from_slice(&key);
        } else {
            // Non-hardened: need public key
            let signing_key = SigningKey::from_bytes((&key).into())
                .map_err(|e| format!("invalid key in derivation: {e}"))?;
            let pubkey = signing_key.verifying_key();
            let compressed = pubkey.to_encoded_point(true);
            data.extend_from_slice(compressed.as_bytes());
        }
        data.extend_from_slice(&child.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|_| "HMAC init failed")?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        // child_key = (parent_key + tweak) mod n
        use k256::elliptic_curve::ops::Reduce;
        use k256::U256 as KU256;

        let tweak_uint = KU256::from_be_slice(&result[0..32]);
        let parent_uint = KU256::from_be_slice(&key);
        let tweak_scalar = <k256::Scalar as Reduce<KU256>>::reduce(tweak_uint);
        let parent_scalar = <k256::Scalar as Reduce<KU256>>::reduce(parent_uint);
        let child_scalar = parent_scalar + tweak_scalar;
        use k256::elliptic_curve::ScalarPrimitive;
        let child_prim: ScalarPrimitive<k256::Secp256k1> = child_scalar.into();
        let child_bytes = child_prim.to_bytes();
        key.copy_from_slice(&child_bytes);
        chain_code.copy_from_slice(&result[32..64]);
    }

    Ok(key)
}
