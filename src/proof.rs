use crate::utils::c;

/// Proof struct, represents the proof generated in the ZKP system
pub struct Proof {
    pub proof_value: u64,
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
