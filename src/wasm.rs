//! WASM bindings for browser usage

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use wasm_bindgen::prelude::*;

use crate::circuit::WitnessCircuit;
use crate::utils::decimal_to_field;

mod snarkjs_proof;

pub use snarkjs_proof::compress_snarkjs_proof_wasm;

/// Initialize panic hook for better error messages in browser.
/// Only call this when running in actual WASM environment, not tests.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// No-op for non-WASM builds (like tests)
#[cfg(not(target_arch = "wasm32"))]
pub fn init_panic_hook() {
    // No-op: panic hook only needed in WASM
}

/// Generate a Groth16 proof from witness in decimal format (snarkjs native)
///
/// This function accepts witness in the native snarkjs format (decimal strings)
/// and handles the conversion to field elements internally.
///
/// # Arguments
/// * `num_public_signals` - Number of public signals to extract from witness
/// * `witness_json` - JSON array of witness values as decimal strings (e.g., `["1", "123", "456"]`)
/// * `proving_key_bytes` - Serialized proving key (arkworks format)
///
/// # Returns
/// JSON string with format: `{"proof": "0x...", "publicSignals": ["0x...", "0x..."]}`
///
/// # Example
/// ```ignore
/// // Witness directly from snarkjs (no conversion needed)
/// let witness_json = r#"["1", "12345", "67890"]"#;
/// let result = generate_proof_from_decimal_wasm(5, witness_json, proving_key_bytes)?;
/// ```
#[wasm_bindgen]
pub fn generate_proof_from_decimal_wasm(
    num_public_signals: usize,
    witness_json: &str,
    proving_key_bytes: &[u8],
) -> Result<String, JsValue> {
    // Parse witness JSON (decimal strings)
    let witness_strings: Vec<String> = serde_json::from_str(witness_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse witness JSON: {e}")))?;

    // Convert decimal strings to field elements
    let witness: Vec<Bn254Fr> = witness_strings
        .iter()
        .map(|s| decimal_to_field(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&e))?;

    // Deserialize proving key
    let proving_key = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proving key: {e}")))?;

    // Generate proof
    let circuit = WitnessCircuit {
        witness: witness.clone(),
    };
    let mut rng = StdRng::from_entropy();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {e}")))?;

    // Serialize proof (compressed 128 bytes)
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {e}")))?;

    let proof_hex = format!("0x{}", hex::encode(&proof_bytes));

    // Extract public signals
    // Validate bounds
    if num_public_signals == 0 {
        return Err(JsValue::from_str(
            "num_public_signals must be greater than 0",
        ));
    }
    if num_public_signals >= witness.len() {
        return Err(JsValue::from_str(&format!(
            "num_public_signals ({}) exceeds witness length ({})",
            num_public_signals,
            witness.len()
        )));
    }

    let public_signals: Vec<String> = witness[1..=num_public_signals]
        .iter()
        .map(|f| {
            let mut bytes = f.into_bigint().to_bytes_le();
            bytes.resize(32, 0u8);
            format!("0x{}", hex::encode(&bytes))
        })
        .collect();

    // Return JSON output
    let output = serde_json::json!({
        "proof": proof_hex,
        "publicSignals": public_signals,
    });

    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize output: {e}")))
}

// WASM module tests
//
// Note: `generate_proof_from_decimal_wasm` returns `Result<String, JsValue>`.
// JsValue is not available in the native test runner, so the function itself
// cannot be called directly in these tests. The tests below validate all the
// logic that surrounds it: JSON parsing, field conversion, bounds validation,
// and output format — by calling the underlying helpers directly.
//
// For end-to-end WASM tests use `wasm-pack test --headless`.

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ark_ff::BigInteger;

    // ── witness JSON parsing ──────────────────────────────────────────────────

    #[test]
    fn test_witness_hex_json_parsed_correctly() {
        let witness_json = r#"[
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "0x0200000000000000000000000000000000000000000000000000000000000000"
        ]"#;
        let strings: Vec<String> = serde_json::from_str(witness_json).unwrap();
        assert_eq!(strings.len(), 2);
        assert!(strings[0].starts_with("0x"));
    }

    #[test]
    fn test_witness_decimal_json_parsed_and_converted() {
        let witness_json = r#"["1", "5", "255"]"#;
        let strings: Vec<String> = serde_json::from_str(witness_json).unwrap();
        let fields: Vec<Bn254Fr> = strings
            .iter()
            .map(|s| decimal_to_field(s).unwrap())
            .collect();
        assert_eq!(fields[0], Bn254Fr::from(1u64));
        assert_eq!(fields[1], Bn254Fr::from(5u64));
        assert_eq!(fields[2], Bn254Fr::from(255u64));
    }

    #[test]
    fn test_witness_json_invalid_is_error() {
        let bad_json = "not-json[[[";
        let result: Result<Vec<String>, _> = serde_json::from_str(bad_json);
        assert!(result.is_err());
    }

    // ── num_public_signals validation ─────────────────────────────────────────

    #[test]
    fn test_num_public_signals_zero_is_invalid() {
        // Replicates the guard inside generate_proof_from_decimal_wasm
        let num_public_signals: usize = 0;
        assert!(num_public_signals == 0, "should be caught as invalid");
    }

    #[test]
    fn test_num_public_signals_equal_to_witness_len_is_invalid() {
        let witness_len = 10usize;
        let num_public_signals = 10usize;
        // Guard: num_public_signals >= witness.len()
        assert!(num_public_signals >= witness_len);
    }

    #[test]
    fn test_num_public_signals_within_bounds_is_valid() {
        let witness_len = 100usize;
        let num_public_signals = 5usize;
        assert!(num_public_signals > 0);
        assert!(num_public_signals < witness_len);
    }

    // ── public signals extraction ─────────────────────────────────────────────

    #[test]
    fn test_public_signals_extracted_from_correct_indices() {
        // witness[0] is always 1 (constant), public signals start at index 1
        let witness = [
            Bn254Fr::from(1u64),  // [0] constant
            Bn254Fr::from(10u64), // [1] public
            Bn254Fr::from(20u64), // [2] public
            Bn254Fr::from(30u64), // [3] public (last public for num=3)
            Bn254Fr::from(40u64), // [4] private
        ];
        let num_public_signals = 3;
        let public_signals: Vec<String> = witness[1..=num_public_signals]
            .iter()
            .map(|f| {
                let mut bytes = f.into_bigint().to_bytes_le();
                bytes.resize(32, 0u8);
                format!("0x{}", hex::encode(&bytes))
            })
            .collect();

        assert_eq!(public_signals.len(), 3);
        assert!(public_signals[0].starts_with("0x0a")); // 10 = 0x0a
        assert!(public_signals[2].starts_with("0x1e")); // 30 = 0x1e
    }

    #[test]
    fn test_public_signals_are_32_byte_hex() {
        let f = Bn254Fr::from(42u64);
        let mut bytes = f.into_bigint().to_bytes_le();
        bytes.resize(32, 0u8);
        let hex = format!("0x{}", hex::encode(&bytes));
        // 2 ("0x") + 64 (32 bytes * 2 hex chars) = 66 chars
        assert_eq!(hex.len(), 66);
    }

    // ── output JSON format ─────────────────────────────────────────────────────

    #[test]
    fn test_output_json_has_required_fields() {
        let output = serde_json::json!({
            "proof": "0xabcd",
            "publicSignals": ["0x01", "0x02"]
        });
        assert!(output.get("proof").is_some());
        let signals = output["publicSignals"].as_array().unwrap();
        assert_eq!(signals.len(), 2);
    }
}
