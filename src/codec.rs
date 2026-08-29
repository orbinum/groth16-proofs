use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::Proof as ArkProof;
use ark_serialize::CanonicalSerialize;

use crate::error::ProofError;
use crate::field::from_decimal_str;

#[derive(serde::Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

fn validate_structure(proof: &SnarkjsProof) -> Result<(), ProofError> {
    if proof.pi_a.len() < 2 {
        return Err(ProofError::SnarkjsProofParse(
            "pi_a must contain at least 2 elements".into(),
        ));
    }
    if proof.pi_b.len() < 2 || proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(ProofError::SnarkjsProofParse(
            "pi_b must be a 2x2 matrix".into(),
        ));
    }
    if proof.pi_c.len() < 2 {
        return Err(ProofError::SnarkjsProofParse(
            "pi_c must contain at least 2 elements".into(),
        ));
    }
    Ok(())
}

fn parse_proof(proof: &SnarkjsProof) -> Result<ArkProof<Bn254>, ProofError> {
    let fq = |s: &str, ctx: &str| {
        from_decimal_str::<Fq>(s).map_err(|e| ProofError::SnarkjsProofParse(format!("{ctx}: {e}")))
    };
    Ok(ArkProof::<Bn254> {
        a: G1Affine::new(
            fq(&proof.pi_a[0], "pi_a[0]")?,
            fq(&proof.pi_a[1], "pi_a[1]")?,
        ),
        b: G2Affine::new(
            Fq2::new(
                fq(&proof.pi_b[0][0], "pi_b[0][0]")?,
                fq(&proof.pi_b[0][1], "pi_b[0][1]")?,
            ),
            Fq2::new(
                fq(&proof.pi_b[1][0], "pi_b[1][0]")?,
                fq(&proof.pi_b[1][1], "pi_b[1][1]")?,
            ),
        ),
        c: G1Affine::new(
            fq(&proof.pi_c[0], "pi_c[0]")?,
            fq(&proof.pi_c[1], "pi_c[1]")?,
        ),
    })
}

/// Parse a snarkjs Groth16 proof JSON string and return 128-byte arkworks compressed proof bytes.
pub fn compress_snarkjs_proof(proof_json: &str) -> Result<Vec<u8>, ProofError> {
    let parsed: SnarkjsProof = serde_json::from_str(proof_json)
        .map_err(|e| ProofError::SnarkjsProofParse(e.to_string()))?;
    validate_structure(&parsed)?;
    let proof = parse_proof(&parsed)?;
    let mut compressed = Vec::new();
    proof
        .serialize_compressed(&mut compressed)
        .map_err(|e| ProofError::ProofSerialization(e.to_string()))?;
    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::BigUint;

    fn fq_to_decimal_string(value: Fq) -> String {
        value
            .into_bigint()
            .to_bytes_le()
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |acc, &byte| {
                (acc << 8) + BigUint::from(byte)
            })
            .to_str_radix(10)
    }

    fn build_valid_snarkjs_proof_json() -> String {
        let a = G1Projective::generator().into_affine();
        let b = G2Projective::generator().into_affine();
        let c = G1Projective::generator().into_affine();
        serde_json::json!({
            "pi_a": [fq_to_decimal_string(a.x), fq_to_decimal_string(a.y)],
            "pi_b": [
                [fq_to_decimal_string(b.x.c0), fq_to_decimal_string(b.x.c1)],
                [fq_to_decimal_string(b.y.c0), fq_to_decimal_string(b.y.c1)]
            ],
            "pi_c": [fq_to_decimal_string(c.x), fq_to_decimal_string(c.y)]
        })
        .to_string()
    }

    #[test]
    fn test_compress_produces_128_bytes() {
        let bytes = compress_snarkjs_proof(&build_valid_snarkjs_proof_json()).unwrap();
        assert_eq!(bytes.len(), 128);
    }

    #[test]
    fn test_compress_matches_arkworks_serialization() {
        let proof_json = build_valid_snarkjs_proof_json();
        let bytes = compress_snarkjs_proof(&proof_json).unwrap();

        let parsed: SnarkjsProof = serde_json::from_str(&proof_json).unwrap();
        let proof = parse_proof(&parsed).unwrap();
        let mut expected = Vec::new();
        proof.serialize_compressed(&mut expected).unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_rejects_malformed_json() {
        assert!(compress_snarkjs_proof("not valid json {{{{").is_err());
    }

    #[test]
    fn test_rejects_short_pi_a() {
        let proof_json = serde_json::json!({
            "pi_a": ["1"],
            "pi_b": [["1", "2"], ["3", "4"]],
            "pi_c": ["1", "2"]
        })
        .to_string();
        let err = compress_snarkjs_proof(&proof_json).unwrap_err();
        assert!(err
            .to_string()
            .contains("pi_a must contain at least 2 elements"));
    }

    #[test]
    fn test_rejects_pi_b_no_rows() {
        let proof = SnarkjsProof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![],
            pi_c: vec!["1".into(), "2".into()],
        };
        let err = validate_structure(&proof).unwrap_err();
        assert!(err.to_string().contains("pi_b must be a 2x2 matrix"));
    }

    #[test]
    fn test_rejects_pi_b_short_rows() {
        let proof = SnarkjsProof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![vec!["1".into()], vec!["3".into(), "4".into()]],
            pi_c: vec!["1".into(), "2".into()],
        };
        let err = validate_structure(&proof).unwrap_err();
        assert!(err.to_string().contains("pi_b must be a 2x2 matrix"));
    }

    #[test]
    fn test_from_decimal_str_fq_invalid() {
        let err = from_decimal_str::<Fq>("not-a-number").unwrap_err();
        assert!(err.contains("Failed to parse decimal string"));
    }
}
