//! Orbinum Groth16 Proof Generator
//!
//! # Architecture
//!
//! - `error`  — [`ProofError`] unified error type
//! - `field`  — generic [`from_decimal_str`] / [`from_hex_le`] field conversion
//! - `circuit`— [`WitnessCircuit`]: arkworks `ConstraintSynthesizer` adapter
//! - `prover` — [`prove_from_witness`]: core prover shared by native and WASM paths
//! - `codec`  — [`codec::compress_snarkjs_proof`]: snarkjs JSON → compressed bytes
//! - `proof`  — [`generate_proof_from_witness`]: file-I/O adapter (native/CLI)
//! - `utils`  — backward-compat shims for `decimal_to_field` / `hex_to_field`
//! - `wasm`   — WASM bindings (`generate_proof_from_decimal_wasm`, `compress_snarkjs_proof_wasm`)

mod circuit;
mod codec;
mod error;
mod field;
mod proof;
mod prover;
mod utils;

#[cfg(feature = "wasm")]
pub mod wasm;

// Core types
pub use circuit::WitnessCircuit;
pub use error::ProofError;

// Proof generation
pub use proof::generate_proof_from_witness;
pub use prover::prove_from_witness;

// snarkjs interop
pub use codec::compress_snarkjs_proof;

// Field conversion
pub use field::{from_decimal_str, from_hex_le};

// Backward-compat aliases
pub use utils::{decimal_to_field, hex_to_field};

// WASM re-exports
#[cfg(feature = "wasm")]
pub use wasm::{compress_snarkjs_proof_wasm, generate_proof_from_decimal_wasm, init_panic_hook};
