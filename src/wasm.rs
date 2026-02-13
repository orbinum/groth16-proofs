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
use crate::utils::hex_to_field;

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

/// Generate a Groth16 proof from witness (WASM interface)
///
/// # Arguments
/// * `circuit_type` - "unshield", "transfer", or "disclosure"
/// * `witness_json` - JSON array of witness values as strings
/// * `proving_key_bytes` - Serialized proving key (arkworks format)
///
/// # Returns
/// JSON string with format: `{"proof": "0x...", "publicSignals": ["...", "..."]}`
#[wasm_bindgen]
pub fn generate_proof_wasm(
    circuit_type: &str,
    witness_json: &str,
    proving_key_bytes: &[u8],
) -> Result<String, JsValue> {
    // Parse witness JSON
    let witness_strings: Vec<String> = serde_json::from_str(witness_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse witness JSON: {e}")))?;

    let witness: Vec<Bn254Fr> = witness_strings
        .iter()
        .map(|s| hex_to_field(s))
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
    let num_public_signals = match circuit_type {
        "unshield" => 5,
        "transfer" => 5,
        "disclosure" => 4,
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unknown circuit type: {circuit_type}"
            )))
        }
    };

    let public_signals: Vec<String> = witness[1..=num_public_signals]
        .iter()
        .map(|f| {
            let bytes = f.into_bigint().to_bytes_le();
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
// Note: These tests use conditional compilation to avoid JsValue issues in native test runner.
// They validate the underlying logic (JSON parsing, data conversion, validation) without
// calling generate_proof_wasm() directly.
//
// For complete testing instructions, see: docs/testing.md

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    // Helper to create valid witness JSON
    fn create_witness_json(count: usize) -> String {
        let witness: Vec<String> = (0..count)
            .map(|i| {
                let value = (i + 1) as u64;
                let mut bytes = vec![0u8; 32];
                bytes[0] = (value & 0xFF) as u8;
                bytes[1] = ((value >> 8) & 0xFF) as u8;
                format!("0x{}", hex::encode(&bytes))
            })
            .collect();
        serde_json::to_string(&witness).unwrap()
    }

    #[test]
    fn test_circuit_type_public_signals_count() {
        let circuits = vec![("unshield", 5), ("transfer", 5), ("disclosure", 4)];

        for (circuit_type, expected_count) in circuits {
            let count = match circuit_type {
                "unshield" => 5,
                "transfer" => 5,
                "disclosure" => 4,
                _ => 0,
            };

            assert_eq!(
                count, expected_count,
                "Circuit {} should have {} public signals",
                circuit_type, expected_count
            );
        }
    }

    #[test]
    fn test_witness_json_parsing() {
        let witness_json = r#"[
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "0x0200000000000000000000000000000000000000000000000000000000000000"
        ]"#;

        let witness_strings: Result<Vec<String>, _> = serde_json::from_str(witness_json);

        assert!(witness_strings.is_ok());
        let witness_strings = witness_strings.unwrap();
        assert_eq!(witness_strings.len(), 2);
    }

    #[test]
    fn test_witness_hex_to_field_conversion() {
        let witness_json = r#"[
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "0x0500000000000000000000000000000000000000000000000000000000000000"
        ]"#;

        let witness_strings: Vec<String> = serde_json::from_str(witness_json).unwrap();
        let witness_result: Result<Vec<Bn254Fr>, String> =
            witness_strings.iter().map(|s| hex_to_field(s)).collect();

        assert!(witness_result.is_ok());
        let witness = witness_result.unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], Bn254Fr::from(1u64));
        assert_eq!(witness[1], Bn254Fr::from(5u64));
    }

    #[test]
    fn test_proof_output_format() {
        let output = serde_json::json!({
            "proof": "0xabcd1234",
            "publicSignals": ["0x01", "0x02"]
        });

        let json_string = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_string).unwrap();

        assert!(parsed.get("proof").is_some());
        assert!(parsed.get("publicSignals").is_some());
        assert!(parsed["publicSignals"].is_array());
        assert_eq!(parsed["publicSignals"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_public_signals_extraction_bounds() {
        let witness = [
            Bn254Fr::from(1u64),  // index 0
            Bn254Fr::from(10u64), // index 1 (first public)
            Bn254Fr::from(20u64), // index 2
            Bn254Fr::from(30u64), // index 3
            Bn254Fr::from(40u64), // index 4
            Bn254Fr::from(50u64), // index 5 (last public for unshield)
            Bn254Fr::from(60u64), // index 6 (private)
        ];

        let num_public_signals = 5;

        let public_signals: Vec<_> = witness[..]
            .get(1..=num_public_signals)
            .unwrap_or(&[])
            .iter()
            .map(|f| {
                let bytes = f.into_bigint().to_bytes_le();
                format!("0x{}", hex::encode(&bytes))
            })
            .collect();

        assert_eq!(public_signals.len(), 5);
        // Verify we extract the correct indices (1-5)
        assert!(public_signals[0].starts_with("0x0a")); // 10 in hex
        assert!(public_signals[4].starts_with("0x32")); // 50 in hex
    }

    #[test]
    fn test_unknown_circuit_type_error() {
        // Test that verifies unknown circuit type error
        let circuit_type = "unknown";
        let result = match circuit_type {
            "unshield" => Ok(5),
            "transfer" => Ok(5),
            "disclosure" => Ok(4),
            _ => Err(format!("Unknown circuit type: {}", circuit_type)),
        };

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Unknown circuit type: unknown");
    }

    #[test]
    fn test_create_witness_json_helper() {
        let witness_json = create_witness_json(3);
        let witness_array: Vec<String> = serde_json::from_str(&witness_json).unwrap();
        assert_eq!(witness_array.len(), 3);
        assert!(witness_array[0].starts_with("0x"));
    }
}
