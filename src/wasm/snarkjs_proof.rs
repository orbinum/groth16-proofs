use crate::codec::compress_snarkjs_proof;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn compress_snarkjs_proof_wasm(proof_json: &str) -> Result<String, JsValue> {
    compress_snarkjs_proof(proof_json)
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
