// Test module, only compiled when running tests
#[cfg(test)]
mod tests {
    use rand::Rng; // Required for random number generation
    use crate::{random_witness, hash_witness, generate_keys, generate_proof, verify_proof}; // Functions required for tests

    // Test to verify the ZKP system with valid data
    #[test]
    fn test_zkp() {
        // Step 1: Generate a random lambda key
        let lambda = rand::thread_rng().gen::<u64>();

        // Step 2: Generate a random witness and its hash
        let witness = random_witness();
        let h = hash_witness(&witness);

        // Step 3: Generate proving and verification keys
        let keys = generate_keys(lambda);

        // Step 4: Generate a proof using the proving key and witness
        let proof = generate_proof(keys.proving_key, &h, &witness)
            .expect("Proof should be generated");

        // Step 5: Verify the proof using the verification key
        assert!(verify_proof(keys.verification_key, &h, proof));
    }

    // Test to ensure that an invalid witness does not generate a proof
    #[test]
    fn test_invalid_witness() {
        // Step 1: Generate a random lambda key
        let lambda = rand::thread_rng().gen::<u64>();

        // Step 2: Generate a random witness and its hash
        let witness = random_witness();
        let h = hash_witness(&witness);

        // Step 3: Generate proving and verification keys
        let keys = generate_keys(lambda);

        // Step 4: Attempt to generate a proof with an incorrect witness
        let invalid_witness = random_witness();
        let proof = generate_proof(keys.proving_key, &h, &invalid_witness);

        // Step 5: Ensure that proof generation fails for an invalid witness
        assert!(proof.is_none());
    }
}
