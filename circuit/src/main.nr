use dep::poseidon;

mod merkle_tree;
fn main(
    root: pub Field,
    nullifier_hash: pub Field,
    recipient: pub Field,
    secret: Field,
    nullifier: Field,
    merkle_proof: [Field; 20],
    is_even: [bool; 20],
) {
    let commitmentHash = poseidon::poseidon2::Poseidon2::hash([nullifier, secret], 2);
    let computed_nullifier_hash = poseidon::poseidon2::Poseidon2::hash([nullifier], 1);
    let computed_root = merkle_tree::compute_merkle_root(commitmentHash, merkle_proof, is_even);
    // let recipient_binding = recipient * recipient;
    // assert(recipient_binding == recipient * recipient);
    assert(computed_nullifier_hash == nullifier_hash);
    assert(computed_root == root);
}
