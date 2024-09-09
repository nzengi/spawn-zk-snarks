use crate::utils::c;

/// KeyPair struct, holds the proving key and verification key pair
pub struct KeyPair {
    pub proving_key: u64,
    pub verification_key: u64,
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
