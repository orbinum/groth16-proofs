use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::Proof as ArkProof;
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use wasm_bindgen::prelude::*;

#[derive(serde::Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

fn parse_fq_decimal(value: &str) -> Result<Fq, String> {
    let bigint = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| format!("Invalid decimal field element: {value}"))?;

    let bytes = bigint.to_bytes_le();
    Ok(Fq::from_le_bytes_mod_order(&bytes))
}

fn validate_snarkjs_proof_structure(parsed: &SnarkjsProof) -> Result<(), String> {
    if parsed.pi_a.len() < 2 {
        return Err(
            "Invalid snarkjs proof structure: pi_a must contain at least 2 elements".to_string(),
        );
    }
    if parsed.pi_b.len() < 2 || parsed.pi_b[0].len() < 2 || parsed.pi_b[1].len() < 2 {
        return Err("Invalid snarkjs proof structure: pi_b must be a 2x2 matrix".to_string());
    }
    if parsed.pi_c.len() < 2 {
        return Err(
            "Invalid snarkjs proof structure: pi_c must contain at least 2 elements".to_string(),
        );
    }

    Ok(())
}

fn snarkjs_to_ark_proof(parsed: &SnarkjsProof) -> Result<ArkProof<Bn254>, String> {
    validate_snarkjs_proof_structure(parsed)?;

    let a = G1Affine::new(
        parse_fq_decimal(&parsed.pi_a[0]).map_err(|e| format!("Invalid pi_a[0]: {e}"))?,
        parse_fq_decimal(&parsed.pi_a[1]).map_err(|e| format!("Invalid pi_a[1]: {e}"))?,
    );

    let b = G2Affine::new(
        Fq2::new(
            parse_fq_decimal(&parsed.pi_b[0][0]).map_err(|e| format!("Invalid pi_b[0][0]: {e}"))?,
            parse_fq_decimal(&parsed.pi_b[0][1]).map_err(|e| format!("Invalid pi_b[0][1]: {e}"))?,
        ),
        Fq2::new(
            parse_fq_decimal(&parsed.pi_b[1][0]).map_err(|e| format!("Invalid pi_b[1][0]: {e}"))?,
            parse_fq_decimal(&parsed.pi_b[1][1]).map_err(|e| format!("Invalid pi_b[1][1]: {e}"))?,
        ),
    );

    let c = G1Affine::new(
        parse_fq_decimal(&parsed.pi_c[0]).map_err(|e| format!("Invalid pi_c[0]: {e}"))?,
        parse_fq_decimal(&parsed.pi_c[1]).map_err(|e| format!("Invalid pi_c[1]: {e}"))?,
    );

    Ok(ArkProof::<Bn254> { a, b, c })
}

/// Compress a snarkjs Groth16 proof into arkworks canonical compressed bytes (128 bytes)
///
/// # Arguments
/// * `proof_json` - JSON string of snarkjs proof with `pi_a`, `pi_b`, `pi_c`
///
/// # Returns
/// Hex string `0x...` with 128 bytes (arkworks compressed proof)
#[wasm_bindgen]
pub fn compress_snarkjs_proof_wasm(proof_json: &str) -> Result<String, JsValue> {
    let parsed: SnarkjsProof = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse snarkjs proof JSON: {e}")))?;
    let proof = snarkjs_to_ark_proof(&parsed).map_err(|e| JsValue::from_str(&e))?;

    let mut compressed = Vec::new();
    proof
        .serialize_compressed(&mut compressed)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize compressed proof: {e}")))?;

    Ok(format!("0x{}", hex::encode(compressed)))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;

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
        let a = G1Affine::generator();
        let b = G2Affine::generator();
        let c = G1Affine::generator();

        serde_json::json!({
            "pi_a": [
                fq_to_decimal_string(a.x),
                fq_to_decimal_string(a.y)
            ],
            "pi_b": [
                [
                    fq_to_decimal_string(b.x.c0),
                    fq_to_decimal_string(b.x.c1)
                ],
                [
                    fq_to_decimal_string(b.y.c0),
                    fq_to_decimal_string(b.y.c1)
                ]
            ],
            "pi_c": [
                fq_to_decimal_string(c.x),
                fq_to_decimal_string(c.y)
            ]
        })
        .to_string()
    }

    #[test]
    fn test_parse_fq_decimal_invalid_input() {
        let result = parse_fq_decimal("not-a-number");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid decimal field element: not-a-number"));
    }

    #[test]
    fn test_validate_snarkjs_proof_structure_rejects_short_pi_a() {
        let parsed = SnarkjsProof {
            pi_a: vec!["1".to_string()],
            pi_b: vec![
                vec!["1".to_string(), "2".to_string()],
                vec!["3".to_string(), "4".to_string()],
            ],
            pi_c: vec!["1".to_string(), "2".to_string()],
        };

        let result = validate_snarkjs_proof_structure(&parsed);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("pi_a must contain at least 2 elements"));
    }

    #[test]
    fn test_compress_snarkjs_proof_matches_arkworks_serialization() {
        let proof_json = build_valid_snarkjs_proof_json();

        let compressed_hex = compress_snarkjs_proof_wasm(&proof_json).unwrap();
        assert!(compressed_hex.starts_with("0x"));

        let parsed: SnarkjsProof = serde_json::from_str(&proof_json).unwrap();
        let proof = snarkjs_to_ark_proof(&parsed).unwrap();
        let mut expected_bytes = Vec::new();
        proof.serialize_compressed(&mut expected_bytes).unwrap();

        let expected_hex = format!("0x{}", hex::encode(expected_bytes));
        assert_eq!(compressed_hex, expected_hex);
    }

    #[test]
    fn test_snarkjs_to_ark_proof_rejects_invalid_structure() {
        let invalid_proof_json = serde_json::json!({
            "pi_a": ["1"],
            "pi_b": [["1", "2"]],
            "pi_c": ["3", "4"]
        })
        .to_string();

        let parsed: SnarkjsProof = serde_json::from_str(&invalid_proof_json).unwrap();
        let result = snarkjs_to_ark_proof(&parsed);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid snarkjs proof structure"));
    }
}
