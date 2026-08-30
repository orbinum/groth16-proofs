//! The wasm-bindgen surface.
//!
//! Bindings only: every function here converts arguments, calls into the
//! library, and converts the result back to something JavaScript can hold. The
//! logic they used to carry inline — witness decoding, hex encoding — now lives
//! in [`crate::core::field`], where a native caller can reach it and where it has
//! tests that run without a browser.

use wasm_bindgen::prelude::*;

use crate::core::field::{field_to_le_hex, witness_from_le_bytes};
use crate::format::artifact::read_ark_v2;
use crate::groth16::prove::{prove_circom, public_inputs};

mod snarkjs_proof;
pub use snarkjs_proof::compress_snarkjs_proof_wasm;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[cfg(not(target_arch = "wasm32"))]
pub fn init_panic_hook() {}

/// Generate a verifiable proof from a `.ark` v2 artifact and a raw witness.
///
/// Replaces the 3.0 entry point, which produced proofs that never verified.
/// Two things changed and both had to:
///
/// * **The artifact carries its matrices.** Proving needs them and a v1 `.ark`
///   has none, so no signature taking only a proving key could have been fixed
///   in place.
/// * **The witness arrives as bytes.** The old path serialized 16,928 field
///   elements to decimal strings — hundreds of kilobytes of JSON text, parsed
///   back one BigUint at a time. Here it is `n × 32` little-endian bytes,
///   exactly what a `.wtns` file already holds.
///
/// The public-signal count is read from the artifact rather than passed in. It
/// is a property of the circuit, and a caller that gets it wrong produces a
/// proof that fails verification with nothing to explain why — which is how the
/// 2.x heuristic shipped a bug.
///
/// Returns `{"proof": "0x…", "publicSignals": ["0x…", …]}` — the proof as 128
/// compressed bytes, the signals as 32-byte little-endian hex.
#[wasm_bindgen]
pub fn generate_proof_wasm(artifact_bytes: &[u8], witness_bytes: &[u8]) -> Result<String, JsValue> {
    let witness = witness_from_le_bytes(witness_bytes).map_err(js_err)?;
    let (pk, matrices) = read_ark_v2(artifact_bytes).map_err(js_err)?;

    let signals: Vec<String> = public_inputs(&matrices, &witness)
        .map_err(js_err)?
        .iter()
        .map(field_to_le_hex)
        .collect();

    let proof = prove_circom(&pk, &matrices, &witness).map_err(js_err)?;

    Ok(format!(
        r#"{{"proof":"0x{}","publicSignals":[{}]}}"#,
        hex::encode(proof),
        signals
            .iter()
            .map(|s| format!(r#""{s}""#))
            .collect::<Vec<_>>()
            .join(",")
    ))
}

/// A library error as the string JavaScript sees.
fn js_err(e: crate::ProofError) -> JsValue {
    JsValue::from_str(&e.to_string())
}
