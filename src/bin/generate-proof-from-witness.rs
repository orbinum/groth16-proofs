#!/usr/bin/env rust
//! Binary for generating Groth16 proofs from witness
//!
//! Usage: generate-proof-from-witness <witness.json> <proving_key.ark> [num_public_signals]
//!
//! Input format (JSON):
//! {
//!   "witness": ["0x01...", "0x02...", ...],
//!   "num_public_signals": 5  // Optional: if not in JSON, use CLI arg
//! }
//!
//! Output format (JSON):
//! {
//!   "proof": "0xabcd...",
//!   "public_signals": ["0x01...", "0x02...", ...]
//! }

use groth16_proofs::generate_proof_from_witness;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Deserialize)]
struct WitnessInput {
    witness: Vec<String>,
    #[serde(default)]
    num_public_signals: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ProofOutput {
    proof: String,
    public_signals: Vec<String>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.len() > 4 {
        eprintln!(
            "Usage: {} <witness.json> <proving_key.ark> [num_public_signals]",
            args[0]
        );
        eprintln!("\nnum_public_signals can be specified either:");
        eprintln!("  1. In witness.json as 'num_public_signals' field");
        eprintln!("  2. As 3rd CLI argument");
        eprintln!("  3. Defaults to 5 if not specified");
        std::process::exit(1);
    }

    let witness_path = &args[1];
    let proving_key_path = &args[2];
    let cli_num_public: Option<usize> = args.get(3).and_then(|s| s.parse().ok());

    // Read witness JSON
    let witness_json = std::fs::read_to_string(witness_path).unwrap_or_else(|e| {
        eprintln!("❌ Failed to read witness file: {e}");
        std::process::exit(1);
    });

    let input: WitnessInput = serde_json::from_str(&witness_json).unwrap_or_else(|e| {
        eprintln!("❌ Failed to parse witness JSON: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "🔐 Generating proof from {} witness elements...",
        input.witness.len()
    );

    // Generate proof
    let proof_bytes =
        generate_proof_from_witness(&input.witness, proving_key_path).unwrap_or_else(|e| {
            eprintln!("❌ Proof generation failed: {e}");
            std::process::exit(1);
        });

    eprintln!("✅ Proof generated: {} bytes", proof_bytes.len());

    // Determine number of public signals
    // Priority: CLI arg > JSON field > default (5)
    let num_public_signals = cli_num_public.or(input.num_public_signals).unwrap_or(5); // Default to 5 (most common for unshield/transfer)

    eprintln!("📊 Extracting {num_public_signals} public signals");

    // Extract public signals (indices 1..n from witness)
    // Index 0 is always 1 (constant), indices 1..n are public inputs
    let public_signals: Vec<String> = input
        .witness
        .iter()
        .skip(1) // Skip index 0 (always 1)
        .take(num_public_signals)
        .cloned()
        .collect();

    if public_signals.len() != num_public_signals {
        eprintln!(
            "⚠️  Warning: Expected {} public signals, got {}",
            num_public_signals,
            public_signals.len()
        );
    }

    // Output result as JSON
    let output = ProofOutput {
        proof: format!("0x{}", hex::encode(&proof_bytes)),
        public_signals,
    };

    let output_json = serde_json::to_string(&output).unwrap_or_else(|e| {
        eprintln!("❌ Failed to serialize output: {e}");
        std::process::exit(1);
    });

    println!("{output_json}");
}
