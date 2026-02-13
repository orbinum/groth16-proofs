//! Orbinum Proof Generator Library
//!
//! Generates Groth16 proofs from pre-calculated witness using arkworks.
//!
//! # Architecture
//!
//! - `utils`: Utility functions (hex conversions)
//! - `circuit`: Circuit wrapper for arkworks
//! - `proof`: Proof generation logic (native Rust)
//! - `wasm`: WASM bindings for browser usage

// Modules
mod circuit;
mod proof;
mod utils;

#[cfg(feature = "wasm")]
pub mod wasm;

// Public exports
pub use circuit::WitnessCircuit;
pub use proof::generate_proof_from_witness;
pub use utils::hex_to_field;

// Re-export WASM functions when feature is enabled
#[cfg(feature = "wasm")]
pub use wasm::{generate_proof_wasm, init_panic_hook};
