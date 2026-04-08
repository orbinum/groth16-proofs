use std::fmt;

#[derive(Debug)]
pub enum ProofError {
    WitnessEmpty,
    WitnessConversion(String),
    ProvingKeyIo(String),
    ProvingKeyParse(String),
    ProveGeneration(String),
    ProofSerialization(String),
    NumPublicSignals(String),
    WitnessJsonParse(String),
    SnarkjsProofParse(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::WitnessEmpty => write!(f, "Witness is empty"),
            ProofError::WitnessConversion(e) => write!(f, "Witness conversion failed: {e}"),
            ProofError::ProvingKeyIo(e) => write!(f, "Failed to read proving key: {e}"),
            ProofError::ProvingKeyParse(e) => write!(f, "Failed to deserialize proving key: {e}"),
            ProofError::ProveGeneration(e) => write!(f, "Failed to generate proof: {e}"),
            ProofError::ProofSerialization(e) => write!(f, "Failed to serialize proof: {e}"),
            ProofError::NumPublicSignals(e) => write!(f, "Invalid num_public_signals: {e}"),
            ProofError::WitnessJsonParse(e) => write!(f, "Failed to parse witness JSON: {e}"),
            ProofError::SnarkjsProofParse(e) => write!(f, "Failed to parse snarkjs proof: {e}"),
        }
    }
}

impl std::error::Error for ProofError {}
