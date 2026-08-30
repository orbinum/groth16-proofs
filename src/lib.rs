//! Orbinum Groth16 proof generation.
//!
//! Proves Circom circuits with arkworks, from a pre-computed witness and a
//! `.ark` v2 artifact. Witness calculation is the caller's job — snarkjs in a
//! browser, a native calculator on a phone — so nothing here depends on a
//! WebAssembly runtime.
//!
//! # Architecture
//!
//! Four layers, and the dependency arrows only ever point down:
//!
//! | Layer | Modules | Responsibility |
//! |---|---|---|
//! | [`core`] | `error`, `field` | The error type and BN254 encodings. Depends on nothing here. |
//! | [`format`] | `artifact`, `snarkjs` | Bytes and text that cross a boundary: the `.ark` v2 container, and snarkjs JSON both directions. |
//! | [`groth16`] | `prove`, `verify` | The protocol: proving under `CircomReduction`, and the pairing check. |
//! | `vendor` | `qap`, `zkey` | `CircomReduction` and `read_zkey`, copied from ark-circom. |
//!
//! Plus `wasm`, the wasm-bindgen surface behind the `wasm` feature, which is
//! bindings only.
//!
//! The layering is the point rather than the filing. `core` cannot reach
//! `groth16`, so a field-conversion helper can never quietly grow a dependency
//! on the prover; `format` cannot reach `groth16`, so parsing a key stays
//! separate from proving with it. Both rules are visible in the directory tree
//! and enforced by the module graph.
//!
//! Every public item is re-exported below, so the layout is an implementation
//! detail: `groth16_proofs::prove_circom` is the path, not
//! `groth16_proofs::groth16::prove::prove_circom`.
//!
//! # Proving
//!
//! ```no_run
//! use groth16_proofs::{prove_circom, public_inputs, read_ark_v2, verify_proof};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let witness: Vec<ark_bn254::Fr> = vec![];
//! let artifact = std::fs::read("unshield_pk.ark")?;
//! let (pk, matrices) = read_ark_v2(&artifact)?;
//!
//! // The proving key costs hundreds of milliseconds to deserialize. Hold it
//! // across proofs rather than reading it per transaction.
//! let proof = prove_circom(&pk, &matrices, &witness)?;
//! assert!(verify_proof(&pk.vk, public_inputs(&matrices, &witness)?, &proof)?);
//! # Ok(())
//! # }
//! ```
//!
//! # Packing a verifying key for the chain
//!
//! ```no_run
//! use groth16_proofs::pack_snarkjs_vk;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let json = std::fs::read_to_string("verification_key_unshield.json")?;
//! let bytes = pack_snarkjs_vk(&json)?;
//! assert_eq!(bytes.len(), 488); // 232 + 8 IC elements × 32
//! # Ok(())
//! # }
//! ```
//!
//! # What 4.0.0 removed
//!
//! `prove_from_witness`, `generate_proof_from_witness` and
//! `generate_proof_from_decimal_wasm` are gone, along with the
//! `generate-proof-from-witness` and `bench-groth16` binaries and the
//! `WitnessCircuit` adapter they shared.
//!
//! All of them proved through arkworks' default QAP reduction, where Circom
//! requires `CircomReduction` — the two compute the H polynomial differently.
//! Every proof they produced was well-formed, exactly 128 bytes, and failed
//! verification. Deprecating them would have meant shipping an API whose only
//! possible use is generating proofs that do not work.
//!
//! `from_hex_le`, `decimal_to_field` and `hex_to_field` are also gone. The last
//! two were 2.x shims; the first had no consumer in this crate or any sibling
//! and carried nine tests of its own — more unit tests than `verify_proof`. Use
//! `from_decimal_str` for snarkjs input and `witness_from_le_bytes` for `.wtns`
//! data. `field_to_le_hex`, which converts the other direction and is what the
//! wasm bindings return public signals as, stays.

pub mod core;
pub mod format;
pub mod groth16;
mod vendor;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use core::error::ProofError;

// Proving and verifying
pub use format::artifact::{
    read_ark_v2, write_ark_v2, ARK_V2_MAGIC, ARK_V2_VERSION, MAX_ARTIFACT_BYTES,
};
pub use groth16::prove::{prove_circom, public_inputs};
pub use groth16::verify::verify_proof;

// Re-exported so a caller can name what `prove_circom` takes without adding
// ark-relations as a direct dependency of their own.
pub use ark_relations::r1cs::ConstraintMatrices;
pub use vendor::zkey::read_zkey;

// snarkjs interop, in both directions.
pub use format::snarkjs::{compress_snarkjs_proof, pack_snarkjs_vk, parse_snarkjs_vk};

// Field conversion
pub use core::field::{
    field_to_le_hex, from_decimal_str, parse_witness_json, witness_from_le_bytes, WitnessFile,
    FIELD_BYTES,
};

// WASM
#[cfg(feature = "wasm")]
pub use wasm::{compress_snarkjs_proof_wasm, generate_proof_wasm, init_panic_hook};
