//! FORS+C: k=8 trees of height a=16, last tree forced-zero via R grinding.

use crate::hash::{self, U256};
use crate::merkle;
use crate::params::*;

/// Derive FORS secret for (tree_idx, leaf_idx).
pub fn fors_secret(sk_seed: U256, tree_idx: u32, leaf_idx: u32) -> U256 {
    let mut data = Vec::with_capacity(32 + 4 + 4 + 4);
    data.extend_from_slice(&hash::to_bytes32(sk_seed));
    data.extend_from_slice(b"fors");
    data.extend_from_slice(&tree_idx.to_be_bytes());
    data.extend_from_slice(&leaf_idx.to_be_bytes());
    hash::mask_n(hash::keccak256(&data))
}

/// Build a single FORS tree. Returns (tree_nodes, root).
fn build_fors_tree(seed: U256, sk_seed: U256, tree_idx: u32) -> (Vec<Vec<U256>>, U256) {
    let n_leaves = 1usize << A;
    let mut leaves = Vec::with_capacity(n_leaves);
    for j in 0..n_leaves {
        let secret = fors_secret(sk_seed, tree_idx, j as u32);
        let leaf_adrs = hash::make_adrs(0, 0, 3, tree_idx, 0, 0, j as u32); // type=FORS_TREE
        leaves.push(hash::th(seed, leaf_adrs, secret));
    }

    // Build Merkle tree over FORS leaves
    let mut nodes = vec![leaves];
    for h in 0..A {
        let prev = &nodes[h];
        let mut level = Vec::with_capacity(prev.len() / 2);
        for idx in (0..prev.len()).step_by(2) {
            let parent_idx = idx / 2;
            let adrs = hash::make_adrs(0, 0, 3, tree_idx, 0, (h + 1) as u32, parent_idx as u32);
            level.push(hash::th_pair(seed, adrs, prev[idx], prev[idx + 1]));
        }
        nodes.push(level);
    }
    let root = nodes[A][0];
    (nodes, root)
}

/// Grind R until last FORS index is zero.
pub fn grind_r(seed: U256, root: U256, message: U256) -> Result<(U256, U256), String> {
    let a_mask = (1u64 << A) - 1;
    let last_shift = (K - 1) * A; // bit 112

    for nonce in 0..10_000_000u32 {
        let mut r_input = Vec::with_capacity(7 + 32);
        r_input.extend_from_slice(b"R_grind");
        r_input.extend_from_slice(&hash::to_bytes32(hash::u256_from_u32(nonce)));
        let r = hash::mask_n(hash::keccak256(&r_input));
        let digest = hash::h_msg(seed, root, r, message);

        // Check last index = 0
        let last_idx = hash::u256_shr(&digest, last_shift) & a_mask;
        if last_idx == 0 {
            return Ok((r, digest));
        }
    }
    Err("R grinding failed".into())
}

/// Sign FORS+C: returns (secrets, auth_paths, fors_pk).
pub fn sign_fors(seed: U256, sk_seed: U256, digest: U256)
    -> Result<(Vec<U256>, Vec<Vec<U256>>, U256), String>
{
    let a_mask = (1u64 << A) - 1;

    // Extract indices
    let mut indices = Vec::with_capacity(K);
    for i in 0..K {
        indices.push((hash::u256_shr(&digest, i * A) & a_mask) as usize);
    }

    // Verify forced-zero
    if indices[K - 1] != 0 {
        return Err("FORS+C forced-zero violated".into());
    }

    let mut secrets = Vec::with_capacity(K);
    let mut auth_paths = Vec::with_capacity(K - 1);
    let mut roots = Vec::with_capacity(K);

    // k-1 normal trees
    for t in 0..(K - 1) {
        let (tree_nodes, root) = build_fors_tree(seed, sk_seed, t as u32);
        secrets.push(fors_secret(sk_seed, t as u32, indices[t] as u32));
        auth_paths.push(merkle::get_auth_path(&tree_nodes, indices[t], A));
        roots.push(root);
    }

    // Last tree: forced-zero, reveal root
    let (_, root_last) = build_fors_tree(seed, sk_seed, (K - 1) as u32);
    // "Secret" for last tree is the root itself, hashed
    let last_adrs = hash::make_adrs(0, 0, 3, (K - 1) as u32, 0, 0, 0);
    secrets.push(root_last);
    roots.push(hash::th(seed, last_adrs, root_last));

    // Compress K roots
    let roots_adrs = hash::make_adrs(0, 0, 4, 0, 0, 0, 0); // type=FORS_ROOTS
    let fors_pk = hash::th_multi(seed, roots_adrs, &roots);

    Ok((secrets, auth_paths, fors_pk))
}
