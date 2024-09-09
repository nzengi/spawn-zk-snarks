use sha2::{Sha256, Digest};
use rand::Rng;

/// c function: A program that verifies if a hash matches a witness.
/// x: hashed value, w: secret witness.
/// Return: Returns true if the hash of w matches x.
pub fn c(x: &[u8], w: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(w);
    let result = hasher.finalize();
    result.as_slice() == x
}

/// random_witness: Generates a random witness.
/// Return: Returns a randomly generated 32-byte witness.
pub fn random_witness() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..32).map(|_| rng.gen::<u8>()).collect()
}

/// hash_witness: Generates a SHA-256 hash for the given witness.
/// witness: The witness data.
/// Return: The SHA-256 hash of the witness.
pub fn hash_witness(witness: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(witness);
    hasher.finalize().to_vec()
}
