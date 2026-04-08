use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use wasm_bindgen::prelude::*;

use crate::field::from_decimal_str;
use crate::prover::prove_from_witness;

mod snarkjs_proof;
pub use snarkjs_proof::compress_snarkjs_proof_wasm;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[cfg(not(target_arch = "wasm32"))]
pub fn init_panic_hook() {}

#[wasm_bindgen]
pub fn generate_proof_from_decimal_wasm(
    num_public_signals: usize,
    witness_json: &str,
    proving_key_bytes: &[u8],
) -> Result<String, JsValue> {
    let witness_strings: Vec<String> = serde_json::from_str(witness_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse witness JSON: {e}")))?;

    let witness: Vec<Bn254Fr> = witness_strings
        .iter()
        .map(|s| from_decimal_str::<Bn254Fr>(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&e))?;

    if num_public_signals == 0 {
        return Err(JsValue::from_str(
            "num_public_signals must be greater than 0",
        ));
    }
    if num_public_signals >= witness.len() {
        return Err(JsValue::from_str(&format!(
            "num_public_signals ({num_public_signals}) exceeds witness length ({})",
            witness.len()
        )));
    }

    // Extract public signals before moving witness into the prover.
    let public_signals: Vec<String> = witness[1..=num_public_signals]
        .iter()
        .map(|f| {
            let mut bytes = f.into_bigint().to_bytes_le();
            bytes.resize(32, 0u8);
            format!("0x{}", hex::encode(&bytes))
        })
        .collect();

    let proof_bytes = prove_from_witness(proving_key_bytes, witness, num_public_signals)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let output = serde_json::json!({
        "proof": format!("0x{}", hex::encode(&proof_bytes)),
        "publicSignals": public_signals,
    });

    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize output: {e}")))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_witness_parse_and_convert() {
        let strings: Vec<String> = serde_json::from_str(r#"["1", "5", "255"]"#).unwrap();
        let fields: Vec<Bn254Fr> = strings
            .iter()
            .map(|s| from_decimal_str::<Bn254Fr>(s).unwrap())
            .collect();
        assert_eq!(fields[0], Bn254Fr::from(1u64));
        assert_eq!(fields[1], Bn254Fr::from(5u64));
        assert_eq!(fields[2], Bn254Fr::from(255u64));
    }

    #[test]
    fn test_public_signals_are_32_byte_hex() {
        let f = Bn254Fr::from(42u64);
        let mut bytes = f.into_bigint().to_bytes_le();
        bytes.resize(32, 0u8);
        let hex = format!("0x{}", hex::encode(&bytes));
        assert_eq!(hex.len(), 66); // "0x" + 64 hex chars
    }

    #[test]
    fn test_output_json_has_required_fields() {
        let output = serde_json::json!({
            "proof": "0xabcd",
            "publicSignals": ["0x01", "0x02"]
        });
        assert!(output.get("proof").is_some());
        assert_eq!(output["publicSignals"].as_array().unwrap().len(), 2);
    }
}
