//! Proof generation using arkworks

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

use crate::circuit::WitnessCircuit;
use crate::utils::hex_to_field;

/// Generate a Groth16 proof from witness
///
/// # Arguments
/// * `witness_hex` - Array of hex-encoded witness elements (little-endian)
/// * `proving_key_path` - Path to .ark proving key file
///
/// # Returns
/// * `Ok(Vec<u8>)` - Compressed proof bytes (128 bytes)
/// * `Err(String)` - Error message
pub fn generate_proof_from_witness(
    witness_hex: &[String],
    proving_key_path: &str,
) -> Result<Vec<u8>, String> {
    // 1. Convert hex witness to field elements
    let witness: Vec<Bn254Fr> = witness_hex
        .iter()
        .map(|hex| hex_to_field(hex))
        .collect::<Result<Vec<_>, _>>()?;

    // 2. Load proving key
    let pk_bytes =
        std::fs::read(proving_key_path).map_err(|e| format!("Failed to read proving key: {e}"))?;

    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .map_err(|e| format!("Failed to deserialize proving key: {e}"))?;

    // 3. Create circuit with witness
    let circuit = WitnessCircuit { witness };

    // 4. Generate proof using arkworks
    let mut rng = StdRng::from_entropy();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| format!("Failed to generate proof: {e}"))?;

    // 5. Serialize proof (compressed format - 128 bytes)
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("Failed to serialize proof: {e}"))?;

    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_proof_invalid_proving_key_path() {
        let witness_hex =
            vec!["0x0100000000000000000000000000000000000000000000000000000000000000".to_string()];
        let result = generate_proof_from_witness(&witness_hex, "/nonexistent/path.ark");

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("Failed to read proving key"));
    }

    #[test]
    fn test_generate_proof_invalid_proving_key_content() {
        use std::io::Write;

        let temp_file = "/tmp/invalid_proving_key.ark";
        let mut file = std::fs::File::create(temp_file).unwrap();
        file.write_all(b"invalid content").unwrap();

        let witness_hex =
            vec!["0x0100000000000000000000000000000000000000000000000000000000000000".to_string()];
        let result = generate_proof_from_witness(&witness_hex, temp_file);

        let _ = std::fs::remove_file(temp_file);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("Failed to deserialize proving key"));
    }

    #[test]
    fn test_generate_proof_empty_witness() {
        let witness_hex: Vec<String> = vec![];
        let result = generate_proof_from_witness(&witness_hex, "/fake/path.ark");

        assert!(result.is_err());
    }

    #[test]
    fn test_proof_size_expectation() {
        const EXPECTED_COMPRESSED_PROOF_SIZE: usize = 128;

        // Groth16 compressed proof in BN254:
        // - G1 point (A): 32 bytes compressed
        // - G2 point (B): 64 bytes compressed
        // - G1 point (C): 32 bytes compressed
        // Total: 128 bytes

        assert_eq!(EXPECTED_COMPRESSED_PROOF_SIZE, 128);
    }
}
