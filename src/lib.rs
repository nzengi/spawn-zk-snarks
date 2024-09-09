use rand::Rng;
use sha2::{Sha256, Digest};

/// Proof struct, represents the proof generated in the ZKP system
pub struct Proof {
    pub proof_value: u64,
}

/// KeyPair struct, holds the proving key and verification key pair
pub struct KeyPair {
    pub proving_key: u64,
    pub verification_key: u64,
}

/// c function: A program that verifies if a hash matches a witness.
/// x: hashed value, w: secret witness.
/// Return: Returns true if the hash of w matches x.
pub fn c(x: &[u8], w: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(w);
    let result = hasher.finalize();
    result.as_slice() == x
}

/// generate_keys: Generates proving key and verification key for ZKP.
/// lambda: Randomly large secret key value.
/// Return: Returns a pair of proving key and verification key.
pub fn generate_keys(lambda: u64) -> KeyPair {
    let proving_key = lambda + (c as usize as u64);
    let verification_key = lambda - (c as usize as u64);
    KeyPair {
        proving_key,
        verification_key,
    }
}

/// generate_proof: Generates a proof given proving key, hash, and witness.
/// pk: Proving key.
/// x: Hash value (SHA-256 hash).
/// w: Secret witness value.
/// Return: If the witness validates the hash, it returns a proof.
pub fn generate_proof(pk: u64, x: &[u8], w: &[u8]) -> Option<Proof> {
    if c(x, w) {
        Some(Proof {
            proof_value: pk + 1,
        })
    } else {
        None
    }
}

/// verify_proof: Verifies if the given proof is valid using the verification key.
/// vk: Verification key.
/// x: Hash value.
/// proof: The proof to be verified.
/// Return: Returns true if the proof is valid, otherwise false.
pub fn verify_proof(vk: u64, _x: &[u8], proof: Proof) -> bool {
    let correct_proof = vk + 2 * (c as usize as u64) + 1;
    proof.proof_value == correct_proof
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp() {
        // Generate a random lambda key
        let lambda = rand::thread_rng().gen::<u64>();

        // Generate a random witness and its hash value
        let witness = random_witness();
        let h = hash_witness(&witness);

        // Generate key pair
        let KeyPair {
            proving_key: pk,
            verification_key: _vk,  // Unused variable vk, so we prefix it with _
        } = generate_keys(lambda);

        // Generate a proof
        let proof = generate_proof(pk, &h, &witness).expect("Proof should be generated");

        // Verify the proof
        assert!(verify_proof(_vk, &h, proof));
    }

    #[test]
    fn test_invalid_witness() {
        // Generate a random lambda key
        let lambda = rand::thread_rng().gen::<u64>();

        // Generate a random witness and its hash value
        let witness = random_witness();
        let h = hash_witness(&witness);

        // Generate key pair
        let KeyPair {
            proving_key: pk,
            verification_key: _vk,  // Unused variable vk, so we prefix it with _
        } = generate_keys(lambda);

        // Attempt to generate proof with an incorrect witness
        let invalid_witness = random_witness();
        let proof = generate_proof(pk, &h, &invalid_witness);

        // Ensure that proof is not generated with an incorrect witness
        assert!(proof.is_none());
    }
}
