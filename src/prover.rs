use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

use crate::circuit::WitnessCircuit;
use crate::error::ProofError;

/// Generate a Groth16 compressed proof from a pre-computed witness.
///
/// * `pk_bytes` — raw bytes of an arkworks compressed proving key (`.ark` format).
/// * `witness`  — full Circom witness vector (index 0 = constant 1).
/// * `num_public_signals` — number of public signals (indices 1..=n in the witness).
///
/// Returns 128 compressed proof bytes on success.
pub fn prove_from_witness(
    pk_bytes: &[u8],
    witness: Vec<Bn254Fr>,
    num_public_signals: usize,
) -> Result<Vec<u8>, ProofError> {
    if witness.is_empty() {
        return Err(ProofError::WitnessEmpty);
    }
    if num_public_signals == 0 {
        return Err(ProofError::NumPublicSignals(
            "must be greater than 0".into(),
        ));
    }
    if num_public_signals >= witness.len() {
        return Err(ProofError::NumPublicSignals(format!(
            "{num_public_signals} >= witness length {}",
            witness.len()
        )));
    }

    let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)
        .map_err(|e| ProofError::ProvingKeyParse(e.to_string()))?;

    let circuit = WitnessCircuit {
        witness,
        num_public_signals,
    };
    let mut rng = StdRng::from_entropy();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| ProofError::ProveGeneration(e.to_string()))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProofError::ProofSerialization(e.to_string()))?;

    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_witness_is_rejected() {
        let result = prove_from_witness(b"dummy", vec![], 5);
        assert!(matches!(result.unwrap_err(), ProofError::WitnessEmpty));
    }

    #[test]
    fn test_zero_public_signals_is_rejected() {
        let w = vec![Bn254Fr::from(1u64); 10];
        let result = prove_from_witness(b"dummy", w, 0);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::NumPublicSignals(_)
        ));
    }

    #[test]
    fn test_num_public_signals_gte_witness_len_is_rejected() {
        let w = vec![Bn254Fr::from(1u64); 10];
        let result = prove_from_witness(b"dummy", w, 10);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::NumPublicSignals(_)
        ));
    }

    #[test]
    fn test_invalid_pk_bytes_are_rejected() {
        let w = vec![Bn254Fr::from(1u64); 10];
        let result = prove_from_witness(b"not a proving key", w, 5);
        assert!(matches!(
            result.unwrap_err(),
            ProofError::ProvingKeyParse(_)
        ));
    }

    #[test]
    fn test_error_messages_are_descriptive() {
        let result = prove_from_witness(b"dummy", vec![Bn254Fr::from(1u64); 10], 0);
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Invalid num_public_signals"));

        let result2 = prove_from_witness(b"dummy", vec![], 5);
        let msg2 = result2.unwrap_err().to_string();
        assert!(msg2.contains("Witness is empty"));
    }
}
