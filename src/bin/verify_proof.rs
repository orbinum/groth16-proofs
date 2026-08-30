//! Verify a compressed Groth16 proof against a verifying key.
//!
//! The pairing check itself is [`groth16_proofs::verify_proof`]. What this adds
//! is the arity check around it: the verifying key states the circuit's real
//! public-signal count, so comparing it against the witness file turns a silent
//! verification failure into a message that names the cause.
//!
//! Two failure modes this is built to catch, both of which produce a proof that
//! generates cleanly and fails only at verification:
//!   * a `num_public_signals` that does not match the circuit (this shipped
//!     once — see CHANGELOG 3.0.0), and
//!   * a proving key from a different trusted setup than the verifying key.
//!
//! Usage:
//!   verify-proof <proof.bin|hex> <vk.bin> <witness.json>
//!
//! `vk.bin` is the arkworks-compressed verifying key emitted by `pack-verifying-key`.
//! `witness.json` is `{"witness": ["<decimal>", …], "num_public_signals": N}` —
//! the same shape `make-fixture.ts` writes; the public inputs are read from
//! indices `1..=N`, mirroring how the prover splits the assignment.
//!
//! Exit code 0 if the proof verifies, 1 otherwise. Prints a one-line verdict.

#[path = "common/mod.rs"]
mod common;

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use groth16_proofs::{parse_witness_json, verify_proof};

/// Read a proof as either raw bytes or a hex string, since the CLI emits hex
/// and a device harness naturally writes bytes.
fn read_proof(path: &str) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    // A 128-byte file is already a proof. Anything else is hex, possibly with a
    // 0x prefix and trailing newline.
    if raw.len() == 128 {
        return Ok(raw);
    }
    let text = String::from_utf8(raw)
        .map_err(|_| format!("{path} is neither 128 raw bytes nor valid UTF-8 hex"))?;
    let text = text.trim().trim_start_matches("0x");
    hex::decode(text).map_err(|e| format!("cannot decode {path} as hex: {e}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("Usage: verify-proof <proof.bin|hex> <vk.bin> <witness.json>".into());
    }
    let (proof_path, vk_path, witness_path) = (&args[1], &args[2], &args[3]);

    // `verify_proof` rejects a wrong length too, and says so. This check stays
    // because it runs before the verifying key is read: a CLI user who passed the
    // wrong file gets told which argument is wrong, rather than a key-parse error
    // from three lines further down.
    let proof_bytes = read_proof(proof_path)?;
    if proof_bytes.len() != 128 {
        return Err(format!(
            "proof is {} bytes, expected 128 — a compressed BN254 Groth16 proof is always 128",
            proof_bytes.len()
        ));
    }
    let vk_bytes = std::fs::read(vk_path).map_err(|e| format!("cannot read {vk_path}: {e}"))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| format!("cannot deserialize verifying key: {e}"))?;

    let witness_json = std::fs::read_to_string(witness_path)
        .map_err(|e| format!("cannot read {witness_path}: {e}"))?;
    let (witness, declared) =
        parse_witness_json(&witness_json).map_err(|e| format!("{witness_path}: {e}"))?;

    let num_public = check_arity(declared, witness.len(), vk.gamma_abc_g1.len())?;

    // Public inputs are witness[1..=n]; index 0 is the constant 1, which
    // arkworks supplies itself.
    let public_inputs = &witness[1..=num_public];

    if verify_proof(&vk, public_inputs, &proof_bytes).map_err(|e| e.to_string())? {
        println!("VALID   {num_public} public signals, 128-byte proof");
        Ok(())
    } else {
        Err(format!(
            "INVALID proof does not verify against {vk_path} ({num_public} public signals)"
        ))
    }
}

/// Reconcile the three sources that state a circuit's arity, returning it.
///
/// The verifying key's `gamma_abc_g1` has one element per public input plus one
/// for the constant, so it states the circuit's real arity. The witness file
/// declares its own. When they disagree the proof and the key are for different
/// circuits, and verification would fail with nothing to explain why — which is
/// the failure this binary exists to name.
///
/// Split out from `run` so it can be tested without spawning a process; the
/// checks are the point of the binary, and a check that is awkward to test is a
/// check that goes untested.
fn check_arity(
    declared: Option<usize>,
    witness_len: usize,
    gamma_abc_len: usize,
) -> Result<usize, String> {
    let num_public = declared.ok_or_else(|| {
        "witness file has no num_public_signals, and guessing it is exactly the bug this \
         binary exists to catch"
            .to_string()
    })?;

    let vk_public = gamma_abc_len.saturating_sub(1);
    if vk_public != num_public {
        return Err(format!(
            "witness declares {num_public} public signals but the verifying key encodes \
             {vk_public} — the proof and the key are for different circuits"
        ));
    }
    if num_public >= witness_len {
        return Err(format!(
            "num_public_signals {num_public} >= witness length {witness_len}"
        ));
    }
    Ok(num_public)
}

fn main() {
    common::main_or_die(run);
}

#[cfg(test)]
mod tests {
    use super::check_arity;

    /// The agreeing case, so the failures below mean something.
    #[test]
    fn matching_arities_are_accepted() {
        assert_eq!(check_arity(Some(7), 16_928, 8).unwrap(), 7);
    }

    /// The bug this binary exists to catch: a key from a different circuit.
    #[test]
    fn a_key_for_another_circuit_is_named_as_such() {
        let err = check_arity(Some(7), 16_928, 5).unwrap_err();
        assert!(err.contains("different circuits"), "got: {err}");
        assert!(err.contains("declares 7"), "got: {err}");
        assert!(err.contains("encodes 4"), "got: {err}");
    }

    /// Guessing the arity is what shipped the 3.0.0 bug, so a witness file
    /// without one is refused rather than inferred.
    #[test]
    fn a_missing_arity_is_refused_rather_than_guessed() {
        let err = check_arity(None, 16_928, 8).unwrap_err();
        assert!(err.contains("num_public_signals"), "got: {err}");
    }

    /// `witness[1..=n]` would panic if n reached the end of the witness. This
    /// turns that into a message.
    #[test]
    fn an_arity_that_overruns_the_witness_is_refused() {
        let err = check_arity(Some(7), 7, 8).unwrap_err();
        assert!(err.contains(">= witness length"), "got: {err}");
    }

    /// A verifying key with an empty IC would `saturating_sub` to zero rather
    /// than underflowing, and must still be rejected against any real witness.
    #[test]
    fn an_empty_verifying_key_does_not_underflow() {
        assert!(check_arity(Some(7), 16_928, 0).is_err());
    }
}
