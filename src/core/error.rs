//! The crate's single error type.
//!
//! `Display` is written by hand rather than derived. Adding `thiserror` to a
//! crate that vendors 576 lines of code specifically to avoid a dependency
//! would be the wrong trade for ten match arms.

use std::fmt;

/// Everything that can go wrong producing or checking a proof.
///
/// Each variant names one failure, and is used only for that failure. A variant
/// reused for something its name does not describe turns an error message into
/// a false lead — which is how `SnarkjsProofParse` came to be reported for
/// arkworks deserialization failures before 3.1.0.
#[derive(Debug)]
pub enum ProofError {
    /// The witness vector had no elements. A Circom witness always has at
    /// least the leading constant 1.
    WitnessEmpty,

    /// A witness byte buffer was not a whole number of 32-byte field elements.
    WitnessLength(String),

    /// A `.ark` artifact or proving key could not be deserialized.
    ProvingKeyParse(String),

    /// `Groth16::create_proof_*` failed.
    ProveGeneration(String),

    /// A proof, key, or artifact could not be serialized.
    ProofSerialization(String),

    /// A witness and a circuit disagreed about shape.
    ///
    /// Covers the whole family: a witness that is not the circuit's width, a
    /// circuit declaring zero instance variables, a public-signal count that does
    /// not match the arity. They share a cause — the witness and the key are for
    /// different circuits, or the caller built the witness wrong — and a caller
    /// cannot act differently on them, so they share a variant. The name is
    /// narrower than the meaning; the message says which case it is.
    NumPublicSignals(String),

    /// A witness JSON file was malformed.
    WitnessJsonParse(String),

    /// snarkjs JSON — a proof or a verifying key — was malformed.
    SnarkjsParse(String),

    /// An arkworks-encoded proof could not be deserialized. Distinct from
    /// [`ProofError::SnarkjsParse`]: this is our own binary format, not JSON
    /// from another implementation.
    ProofDeserialization(String),

    /// The pairing check itself errored. Note that this is not "the proof is
    /// invalid" — that is `Ok(false)` — but that verification could not run.
    Verification(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::WitnessEmpty => write!(f, "Witness is empty"),
            ProofError::WitnessLength(e) => write!(f, "Invalid witness length: {e}"),
            ProofError::ProvingKeyParse(e) => write!(f, "Failed to deserialize proving key: {e}"),
            ProofError::ProveGeneration(e) => write!(f, "Failed to generate proof: {e}"),
            ProofError::ProofSerialization(e) => write!(f, "Failed to serialize proof: {e}"),
            ProofError::NumPublicSignals(e) => write!(f, "Invalid num_public_signals: {e}"),
            ProofError::WitnessJsonParse(e) => write!(f, "Failed to parse witness JSON: {e}"),
            ProofError::SnarkjsParse(e) => write!(f, "Failed to parse snarkjs JSON: {e}"),
            ProofError::ProofDeserialization(e) => write!(f, "Failed to deserialize proof: {e}"),
            ProofError::Verification(e) => write!(f, "Verification errored: {e}"),
        }
    }
}

impl std::error::Error for ProofError {}
