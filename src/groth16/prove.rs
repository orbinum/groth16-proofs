//! Proving with the QAP reduction Circom actually uses.
//!
//! Arkworks and Circom compute the H polynomial differently. Arkworks derives
//! its coefficients as (AB-C)/Z in the evaluation domain and transforms back;
//! snarkjs precomputes Lagrange bases over a domain twice as large and takes the
//! odd coefficients of (AB-C). Same statement, different witness map — and a
//! proof built with the wrong one is well-formed, deserializes cleanly, and
//! **never verifies**.
//!
//! That is what this crate did until 3.1.0, through a `prove_from_witness` that
//! has since been removed. Every proof it produced was well-formed, exactly 128
//! bytes, and unverifiable. Nothing caught it because the tests asserted on the
//! length of the output and never on whether it verified.
//!
//! The cost of correctness is that proving needs the circuit's constraint
//! matrices as well as the proving key, which is why a `.ark` v2 artifact
//! carries both. For the unshield circuit the matrices are about 0.9 MB against
//! the key's 3.6 MB, so shipping them is not the obstacle it might sound like.
//!
//! Only the A and B matrices are read: `CircomReduction`'s witness map computes
//! C from the A and B evaluations rather than from `matrices.c`, so an empty C —
//! which is what [`read_zkey`](crate::read_zkey) returns — is correct and not a
//! missing piece.

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;

use crate::core::error::ProofError;
use crate::vendor::qap::CircomReduction;

/// Generate a verifiable Groth16 proof from a Circom witness.
///
/// * `pk` — the proving key, already deserialized. Deserializing it costs
///   seconds on a phone, so it is taken by reference: hold one across many
///   proofs rather than parsing per call.
/// * `matrices` — the circuit's constraint matrices, as
///   [`read_ark_v2`](crate::read_ark_v2) or [`read_zkey`](crate::read_zkey)
///   returns them.
/// * `witness` — the full Circom witness vector, index 0 being the constant 1.
///
/// The number of public signals is read from `matrices.num_instance_variables`
/// rather than taken as an argument. That value comes from the proving key
/// itself, so it cannot disagree with it — unlike a caller-supplied count, which
/// silently produces an unverifiable proof when wrong. That exact bug shipped
/// once (see CHANGELOG 3.0.0).
///
/// Returns the 128-byte compressed proof.
pub fn prove_circom(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Bn254Fr>,
    witness: &[Bn254Fr],
) -> Result<Vec<u8>, ProofError> {
    if witness.is_empty() {
        return Err(ProofError::WitnessEmpty);
    }
    let num_inputs = matrices.num_instance_variables;

    // The witness must be exactly as wide as the circuit, not merely wide enough
    // to cover the public signals.
    //
    // Checking only `num_inputs` leaves the constraint matrices free to reference
    // any column up to the circuit's real width, and arkworks indexes the witness
    // with those columns unchecked (ark-groth16 0.5.0, r1cs_to_qap.rs:29, reached
    // from vendor::qap). Measured on value_proof, whose 5 instance variables sit
    // in a 1157-wide circuit: every witness length from 5 to 1155 panicked. In
    // wasm — where `generate_proof_wasm` calls this — there is no unwinding, so
    // that is the whole module aborting.
    //
    // The width is `instance + witness - 1`: the constant 1 at index 0 is counted
    // by both halves. Measured across all three published circuits (value_proof
    // 5+1152=1157 vs 1156, transfer 8+33723=33731 vs 33730, unshield
    // 8+16921=16929 vs 16928), the difference is exactly 1 in each.
    //
    // The upper bound matters too, and for a quieter reason: an overlong witness
    // used to be accepted, and `msm_bigint` silently truncates it, so the caller
    // got a well-formed proof that could never verify and no indication why.
    let width = num_inputs
        .checked_add(matrices.num_witness_variables)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| {
            ProofError::NumPublicSignals(
                "the circuit's declared width overflows — the matrices are corrupt".into(),
            )
        })?;
    if witness.len() != width {
        return Err(ProofError::NumPublicSignals(format!(
            "the circuit is {width} variables wide ({num_inputs} instance + {} witness, \
             sharing the constant at index 0) but the witness has {}",
            matrices.num_witness_variables,
            witness.len()
        )));
    }

    let mut rng = StdRng::from_entropy();
    let r = Bn254Fr::rand(&mut rng);
    let s = Bn254Fr::rand(&mut rng);

    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        pk,
        r,
        s,
        matrices,
        num_inputs,
        matrices.num_constraints,
        witness,
    )
    .map_err(|e| ProofError::ProveGeneration(e.to_string()))?;

    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| ProofError::ProofSerialization(e.to_string()))?;
    Ok(bytes)
}

/// The public signals of a witness: indices `1..num_instance_variables`.
///
/// Index 0 is the constant 1, which arkworks supplies itself and a verifier does
/// not take. The wasm bindings open-coded this slice with their own off-by-one
/// risk, which is why it lives here now. `src/bin/verify_proof.rs` keeps a
/// separate version deliberately: it has a verifying key but no
/// `ConstraintMatrices`, so it derives the arity from `gamma_abc_g1` instead and
/// cross-checks the two sources rather than trusting one.
///
/// Returns an error rather than slicing blindly when the witness is shorter
/// than the circuit's instance count. That case is reachable from untrusted
/// input — a truncated `.wtns`, or an artifact paired with the wrong witness —
/// and this function is called *before* [`prove_circom`] in the wasm bindings,
/// so a panic here aborts the whole module in a browser instead of surfacing a
/// message the caller can act on.
pub fn public_inputs<'a>(
    matrices: &ConstraintMatrices<Bn254Fr>,
    witness: &'a [Bn254Fr],
) -> Result<&'a [Bn254Fr], ProofError> {
    let needed = matrices.num_instance_variables;
    // Zero is not merely degenerate: `&witness[1..0]` panics on the reversed
    // range, and a forged artifact can declare it.
    if needed == 0 {
        return Err(ProofError::NumPublicSignals(
            "the circuit declares 0 instance variables; a Circom witness always \
             has at least the constant 1"
                .into(),
        ));
    }
    if witness.len() < needed {
        return Err(ProofError::NumPublicSignals(format!(
            "the circuit has {needed} instance variables but the witness has only {}",
            witness.len()
        )));
    }
    Ok(&witness[1..needed])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrices(instance_vars: usize) -> ConstraintMatrices<Bn254Fr> {
        ConstraintMatrices::<Bn254Fr> {
            num_instance_variables: instance_vars,
            num_witness_variables: 0,
            num_constraints: 1,
            a_num_non_zero: 0,
            b_num_non_zero: 0,
            c_num_non_zero: 0,
            a: vec![],
            b: vec![],
            c: vec![],
        }
    }

    /// The public inputs are the witness minus its leading constant. Off by one
    /// here is not an error, it is a proof that verifies against the wrong
    /// statement, so it is worth pinning.
    #[test]
    fn public_inputs_skip_the_constant() {
        let witness: Vec<Bn254Fr> = (0..10u64).map(Bn254Fr::from).collect();
        let got = public_inputs(&matrices(8), &witness).unwrap();
        assert_eq!(got.len(), 7);
        assert_eq!(got[0], Bn254Fr::from(1u64));
        assert_eq!(got[6], Bn254Fr::from(7u64));
    }

    /// A witness with no room for the declared instance variables is rejected
    /// rather than proving something the verifier cannot check.
    #[test]
    fn public_inputs_are_empty_when_only_the_constant_is_present() {
        assert!(public_inputs(&matrices(1), &[Bn254Fr::from(1u64)])
            .unwrap()
            .is_empty());
    }

    /// A witness shorter than the circuit's instance count must be an error,
    /// not a panic. The wasm bindings call this before `prove_circom`, so its
    /// own length check never runs — a slice out of range there takes down the
    /// whole module in a browser.
    #[test]
    fn a_witness_shorter_than_the_instance_count_is_an_error() {
        let short: Vec<Bn254Fr> = (0..4u64).map(Bn254Fr::from).collect();
        let err = public_inputs(&matrices(8), &short).unwrap_err();
        assert!(err.to_string().contains("only 4"), "got: {err}");
    }

    /// Zero instance variables would slice `[1..0]`, which panics on the
    /// reversed range rather than yielding an empty slice. A forged artifact can
    /// declare it, and this is reachable from the wasm entry point.
    #[test]
    fn a_circuit_declaring_zero_instance_variables_is_refused() {
        let witness: Vec<Bn254Fr> = (0..4u64).map(Bn254Fr::from).collect();
        let err = public_inputs(&matrices(0), &witness).unwrap_err();
        assert!(
            err.to_string().contains("0 instance variables"),
            "got: {err}"
        );
    }

    /// The exact boundary: a witness of precisely the instance count is fine.
    #[test]
    fn a_witness_of_exactly_the_instance_count_is_accepted() {
        let exact: Vec<Bn254Fr> = (0..8u64).map(Bn254Fr::from).collect();
        assert_eq!(public_inputs(&matrices(8), &exact).unwrap().len(), 7);
    }

    // `prove_circom` rejecting an empty witness needs a real proving key to
    // exercise, so it lives in tests/adversarial.rs rather than being faked here.
}
