use ark_bn254::Fr as Bn254Fr;

use crate::error::ProofError;
use crate::field::from_hex_le;
use crate::prover::prove_from_witness;

/// Generate a Groth16 proof from a hex-LE witness array and a `.ark` proving key at `path`.
///
/// This is the file-I/O adapter: it reads the proving key from disk and delegates
/// proof generation to [`prove_from_witness`].
pub fn generate_proof_from_witness(
    witness_hex: &[String],
    proving_key_path: &str,
    num_public_signals: usize,
) -> Result<Vec<u8>, ProofError> {
    let witness: Vec<Bn254Fr> = witness_hex
        .iter()
        .map(|h| from_hex_le(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProofError::WitnessConversion)?;

    let pk_bytes =
        std::fs::read(proving_key_path).map_err(|e| ProofError::ProvingKeyIo(e.to_string()))?;

    prove_from_witness(&pk_bytes, witness, num_public_signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_proof_invalid_proving_key_path() {
        let witness_hex =
            vec!["0x0100000000000000000000000000000000000000000000000000000000000000".to_string()];
        let result = generate_proof_from_witness(&witness_hex, "/nonexistent/path.ark", 5);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read proving key"));
    }

    #[test]
    fn test_generate_proof_invalid_proving_key_content() {
        use std::io::Write;
        let temp_file = "/tmp/invalid_proving_key.ark";
        let mut file = std::fs::File::create(temp_file).unwrap();
        file.write_all(b"invalid content").unwrap();

        // Need witness longer than num_public_signals so we reach PK deserialization.
        let witness_hex: Vec<String> = (0..10).map(|i| format!("0x{:064x}", i)).collect();
        let result = generate_proof_from_witness(&witness_hex, temp_file, 5);
        let _ = std::fs::remove_file(temp_file);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to deserialize proving key"));
    }

    #[test]
    fn test_generate_proof_empty_witness() {
        let result = generate_proof_from_witness(&[], "/fake/path.ark", 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_proof_invalid_hex_in_witness() {
        let witness_hex = vec!["0xGGGGGGGG".to_string()];
        let result = generate_proof_from_witness(&witness_hex, "/fake/path.ark", 5);
        assert!(result.is_err());
    }
}
