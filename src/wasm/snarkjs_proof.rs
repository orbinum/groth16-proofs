//! The snarkjs-proof binding, kept beside the rest of the wasm surface.

use wasm_bindgen::prelude::*;

use crate::format::snarkjs::compress_snarkjs_proof;

/// A snarkjs proof JSON as the `0x`-prefixed hex of its 128 compressed bytes.
#[wasm_bindgen]
pub fn compress_snarkjs_proof_wasm(proof_json: &str) -> Result<String, JsValue> {
    compress_snarkjs_proof(proof_json)
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .map_err(super::js_err)
}
