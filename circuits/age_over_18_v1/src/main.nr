// age_over_18_v1 - ZK circuit for anonymous age verification
//
// Proves: user is 18+ (birth_date_days <= cutoff_date_days)
// without revealing actual birth date.
//
// Also proves:
// - Credential signed by trusted Issuer (EdDSA BabyJubJub + Poseidon)
// - Issuer belongs to trusted set (Merkle inclusion, Poseidon, depth 16)
// - subject_tag and nullifier correctly derived

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_4;
use poseidon::poseidon::PoseidonHasher;
use eddsa::eddsa_verify;

// Merkle tree depth for issuer policy
global TREE_DEPTH: u32 = 16;

fn main(
    // --- Private inputs ---
    birth_date_days: Field,
    holder_secret: Field,
    issuer_pubkey_x: Field,
    issuer_pubkey_y: Field,
    sig_r8x: Field,
    sig_r8y: Field,
    sig_s: Field,
    merkle_path: [Field; TREE_DEPTH],
    merkle_index_bits: [Field; TREE_DEPTH],
    idempotency_key_hash: Field,
    // --- Public inputs ---
    verifier_id_hash: pub Field,
    fact_type_hash: pub Field,
    issuer_policy_root: pub Field,
    schema_hash: pub Field,
    subject_tag: pub Field,
    nullifier: pub Field,
    valid_until: pub Field,
    cutoff_date_days: pub Field,
) {
    // 1. Age predicate: birth_date_days <= cutoff_date_days
    let birth_days_u64 = birth_date_days as u64;
    let cutoff_days_u64 = cutoff_date_days as u64;
    assert(birth_days_u64 <= cutoff_days_u64, "Age predicate failed: too young");

    // 2. EdDSA signature verification
    //    Issuer signs: credential_hash = Poseidon4(pubkey_x, pubkey_y, birth_date_days, schema_hash)
    let credential_hash = hash_4([issuer_pubkey_x, issuer_pubkey_y, birth_date_days, schema_hash]);
    let sig_valid = eddsa_verify::<PoseidonHasher>(
        issuer_pubkey_x,
        issuer_pubkey_y,
        sig_s,
        sig_r8x,
        sig_r8y,
        credential_hash,
    );
    assert(sig_valid, "EdDSA signature verification failed");

    // 3. Merkle inclusion proof: issuer is in the trusted policy tree
    //    leaf = Poseidon2(issuer_pubkey_x, issuer_pubkey_y)
    let leaf = hash_2([issuer_pubkey_x, issuer_pubkey_y]);
    let computed_root = compute_merkle_root(leaf, merkle_path, merkle_index_bits);
    assert(computed_root == issuer_policy_root, "Issuer not in policy tree");

    // 4. subject_tag = Poseidon2(holder_secret, verifier_id_hash)
    let computed_subject_tag = hash_2([holder_secret, verifier_id_hash]);
    assert(computed_subject_tag == subject_tag, "subject_tag mismatch");

    // 5. nullifier = Poseidon4(holder_secret, verifier_id_hash, fact_type_hash, idempotency_key_hash)
    let computed_nullifier = hash_4([holder_secret, verifier_id_hash, fact_type_hash, idempotency_key_hash]);
    assert(computed_nullifier == nullifier, "nullifier mismatch");

    // 6. valid_until must be nonzero (basic sanity)
    assert(valid_until != 0, "valid_until must be set");
}

// Compute Merkle root from leaf, path siblings, and direction bits
fn compute_merkle_root(
    leaf: Field,
    path: [Field; TREE_DEPTH],
    index_bits: [Field; TREE_DEPTH],
) -> Field {
    let mut current = leaf;
    for i in 0..TREE_DEPTH {
        let bit = index_bits[i];
        // bit == 0: current is left child, sibling is right
        // bit == 1: current is right child, sibling is left
        let left = if bit == 0 { current } else { path[i] };
        let right = if bit == 0 { path[i] } else { current };
        current = hash_2([left, right]);
    }
    current
}
