//! The test this crate was missing: prove, then verify, in one run.
//!
//! Its absence is why `prove_from_witness` shipped producing proofs that never
//! verified. Every existing test for it is negative — empty witness, zero public
//! signals, invalid key bytes — and the happy path only ever asserted that the
//! output was 128 bytes long. It always was. It was also always invalid.
//!
//! Needs artifacts from the sibling `circuits` repo. Skips rather than fails when
//! they are absent, so a checkout without them still runs green:
//!
//!   cd ../circuits && pnpm run convert:unshield \
//!                  && pnpm exec ts-node scripts/utils/make-fixture.ts
mod common;

use ark_bn254::Fr as Bn254Fr;
use common::artifact;
use groth16_proofs::{prove_circom, public_inputs, read_zkey, verify_proof};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// The witness plus its declared arity, which every test here needs.
fn load_witness(path: &Path) -> (Vec<Bn254Fr>, usize) {
    let (w, n) = common::load_witness(path);
    (w, n.expect("fixture declares num_public_signals"))
}

#[test]
fn unshield_proof_verifies() {
    let (Some(zkey), Some(wit)) = (
        artifact("keys/unshield_pk.zkey"),
        artifact("fixtures/unshield.witness.json"),
    ) else {
        common::assert_artifacts();
        eprintln!("skipping: circuits artifacts not present");
        return;
    };

    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    let (witness, declared_public) = load_witness(&wit);

    // The fixture and the proving key must agree on arity. They disagree exactly
    // when someone regenerates one without the other.
    assert_eq!(
        matrices.num_instance_variables - 1,
        declared_public,
        "proving key and fixture disagree on the number of public signals"
    );

    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    assert_eq!(
        proof.len(),
        128,
        "a compressed BN254 Groth16 proof is 128 bytes"
    );

    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");
    assert!(
        verify_proof(&pk.vk, inputs, &proof).expect("verify"),
        "proof does not verify — this is what the wrong QAP reduction looks like"
    );
}

#[test]
fn a_tampered_public_input_fails_verification() {
    let (Some(zkey), Some(wit)) = (
        artifact("keys/unshield_pk.zkey"),
        artifact("fixtures/unshield.witness.json"),
    ) else {
        common::assert_artifacts();
        eprintln!("skipping: circuits artifacts not present");
        return;
    };

    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    let (witness, _) = load_witness(&wit);
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");

    // Without this half, the test above would pass against a verifier that
    // returns true unconditionally.
    let mut inputs = public_inputs(&matrices, &witness)
        .expect("witness fits the circuit")
        .to_vec();
    inputs[2] += Bn254Fr::from(1u64); // the withdrawal amount
    assert!(
        !verify_proof(&pk.vk, &inputs, &proof).expect("verify"),
        "verification accepted a public input the proof was not made for"
    );
}

#[test]
fn ark_v2_round_trips_and_proves() {
    let (Some(zkey), Some(wit)) = (
        artifact("keys/unshield_pk.zkey"),
        artifact("fixtures/unshield.witness.json"),
    ) else {
        common::assert_artifacts();
        eprintln!("skipping: circuits artifacts not present");
        return;
    };

    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    let blob = groth16_proofs::write_ark_v2(&pk, &matrices).expect("write");
    let (pk2, matrices2) = groth16_proofs::read_ark_v2(&blob).expect("read");

    assert_eq!(
        matrices2.num_instance_variables,
        matrices.num_instance_variables
    );
    assert_eq!(matrices2.num_constraints, matrices.num_constraints);

    // The point of the format is that a proof made from the round-tripped
    // artifact is as good as one made from the zkey. Anything less and the
    // artifact is a smaller file that cannot do the job.
    let (witness, _) = load_witness(&wit);
    let proof = prove_circom(&pk2, &matrices2, &witness).expect("prove");
    let inputs = public_inputs(&matrices2, &witness).expect("witness fits the circuit");
    assert!(
        verify_proof(&pk2.vk, inputs, &proof).expect("verify"),
        "a proof from a round-tripped .ark v2 does not verify"
    );
}

#[test]
fn the_shipped_ark_v2_artifact_proves_and_verifies() {
    let (Some(ark), Some(wit)) = (
        artifact("keys/unshield_pk.ark"),
        artifact("fixtures/unshield.witness.json"),
    ) else {
        common::assert_artifacts();
        eprintln!("skipping: circuits artifacts not present");
        return;
    };

    // The end of the chain: the exact bytes the package publishes, proving
    // without a .zkey anywhere in reach. If this passes, a browser or a phone
    // can do the same with one 4.8 MB download.
    let bytes = std::fs::read(&ark).expect("read artifact");
    let (pk, matrices) = groth16_proofs::read_ark_v2(&bytes).expect("read .ark v2");

    let (witness, _) = load_witness(&wit);
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");
    assert!(
        verify_proof(&pk.vk, inputs, &proof).expect("verify"),
        "the published .ark v2 does not produce a verifying proof"
    );
}
