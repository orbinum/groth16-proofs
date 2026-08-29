//! Checking a proof.
//!
//! Separate from [`prove`](crate::groth16::prove) because verification is independent of
//! the QAP reduction: the pairing check reads the proof and the verifying key
//! and nothing else, so none of the `CircomReduction` reasoning that governs
//! proving applies here. A proof made with the wrong reduction fails this check
//! exactly the way a forged one does.
//!
//! Which is the point. Before 3.1.0 this crate could not verify at all, and
//! that is how the wrong-reduction bug survived two major versions: every test
//! asserted that proving returned 128 bytes, and 128 bytes of garbage look
//! exactly like a proof.

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

use crate::core::error::ProofError;

/// Verify a compressed proof against a verifying key and its public inputs.
///
/// Returns `Ok(false)` for a well-formed proof that does not satisfy the
/// statement, and `Err` only when the check could not run — malformed proof
/// bytes, or a pairing failure. Callers that treat any `Err` as "invalid" are
/// correct to reject, but the distinction matters for diagnosis: `Ok(false)` is
/// a wrong proof, `Err` is a wrong input.
pub fn verify_proof(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Bn254Fr],
    proof_bytes: &[u8],
) -> Result<bool, ProofError> {
    // A Groth16 proof on BN254 is exactly 128 bytes: G1 + G2 + G1 compressed.
    // `deserialize_compressed` reads from the front of the slice and ignores what
    // follows, so a 129-byte input whose first 128 bytes are valid would verify —
    // two encodings of one proof, which matters wherever proof bytes are hashed.
    // The CLI checked this and the library did not, which was backwards: the
    // library is what the chain-facing consumers call.
    const PROOF_BYTES: usize = 128;
    if proof_bytes.len() != PROOF_BYTES {
        return Err(ProofError::ProofDeserialization(format!(
            "a Groth16 proof is {PROOF_BYTES} bytes, got {}",
            proof_bytes.len()
        )));
    }

    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ProofError::ProofDeserialization(e.to_string()))?;
    Groth16::<Bn254>::verify(vk, public_inputs, &proof)
        .map_err(|e| ProofError::Verification(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Garbage bytes are a deserialization failure, not a verification failure.
    /// Reporting them as the latter — which this crate did until the error
    /// variants were split — sends a reader looking at the wrong thing.
    #[test]
    fn malformed_proof_bytes_are_reported_as_deserialization() {
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: Default::default(),
            beta_g2: Default::default(),
            gamma_g2: Default::default(),
            delta_g2: Default::default(),
            gamma_abc_g1: vec![Default::default()],
        };
        let err = verify_proof(&vk, &[], &[0xAB; 64]).unwrap_err();
        assert!(
            matches!(err, ProofError::ProofDeserialization(_)),
            "got: {err:?}"
        );
        assert!(err.to_string().contains("deserialize proof"));
    }

    #[test]
    fn an_empty_proof_is_refused() {
        let vk = VerifyingKey::<Bn254> {
            alpha_g1: Default::default(),
            beta_g2: Default::default(),
            gamma_g2: Default::default(),
            delta_g2: Default::default(),
            gamma_abc_g1: vec![Default::default()],
        };
        assert!(verify_proof(&vk, &[], &[]).is_err());
    }
}
