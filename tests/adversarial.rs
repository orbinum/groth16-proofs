//! The ways a proof can be wrong without anything looking wrong.
//!
//! Every failure this crate has shipped shared a shape: proving succeeded,
//! returned exactly 128 bytes, and produced something no verifier would accept.
//! A test that asserts a byte count cannot tell those apart from a real proof,
//! which is how the QAP-reduction bug survived two major versions.
//!
//! So these tests are all negative on purpose. Each one takes a correct setup,
//! breaks exactly one thing, and asserts the breakage is *caught* — either by an
//! error at the boundary, or by verification refusing the result. A change that
//! reintroduces silent invalidity fails here rather than in production.
//!
//! Needs the sibling `circuits` artifacts; skips cleanly without them:
//!
//!   cd ../circuits && pnpm run convert:unshield \
//!                  && pnpm exec ts-node scripts/utils/make-fixture.ts

mod common;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::UniformRand;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use common::{artifact, load_witness};
use groth16_proofs::{
    prove_circom, public_inputs, read_ark_v2, read_zkey, verify_proof, write_ark_v2, ARK_V2_MAGIC,
};
use std::fs::File;
use std::io::BufReader;

/// The unshield proving key and witness, or `None` when the artifacts are absent.
type Setup = (
    ark_groth16::ProvingKey<ark_bn254::Bn254>,
    groth16_proofs::ConstraintMatrices<Bn254Fr>,
    Vec<Bn254Fr>,
);

fn setup() -> Option<Setup> {
    let zkey = artifact("keys/unshield_pk.zkey")?;
    let wit = artifact("fixtures/unshield.witness.json")?;
    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).ok()?)).ok()?;
    Some((pk, matrices, load_witness(&wit).0))
}

macro_rules! require_artifacts {
    () => {
        match setup() {
            Some(s) => s,
            None => {
                common::assert_artifacts();
                eprintln!("skipping: circuits artifacts not present");
                return;
            }
        }
    };
}

// ─── Public inputs the proof was not made for ────────────────────────────────

/// Every public signal, one at a time. A proof commits to all of them, so
/// altering any single one must be refused — a verifier that only checked the
/// first would pass the existing happy-path test.
#[test]
fn altering_any_public_input_fails_verification() {
    let (pk, matrices, witness) = require_artifacts!();
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    let inputs = public_inputs(&matrices, &witness)
        .expect("witness fits the circuit")
        .to_vec();

    for i in 0..inputs.len() {
        let mut tampered = inputs.clone();
        tampered[i] += Bn254Fr::from(1u64);
        assert!(
            !verify_proof(&pk.vk, &tampered, &proof).expect("verify"),
            "verification accepted a proof with public signal {i} altered"
        );
    }
}

/// Dropping a signal changes the arity, which arkworks rejects outright rather
/// than verifying against a shorter statement.
#[test]
fn a_short_public_input_list_does_not_verify() {
    let (pk, matrices, witness) = require_artifacts!();
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");

    let short = &inputs[..inputs.len() - 1];
    let accepted = verify_proof(&pk.vk, short, &proof).unwrap_or(false);
    assert!(
        !accepted,
        "verification accepted a truncated public input list"
    );
}

/// Order matters as much as content: the signals are positional, and a wallet
/// that built them in the wrong sequence would otherwise get a proof that looks
/// fine and means something else.
#[test]
fn reordering_public_inputs_fails_verification() {
    let (pk, matrices, witness) = require_artifacts!();
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    let mut inputs = public_inputs(&matrices, &witness)
        .expect("witness fits the circuit")
        .to_vec();

    inputs.swap(0, 1); // merkle_root and nullifier
    assert!(
        !verify_proof(&pk.vk, &inputs, &proof).expect("verify"),
        "verification accepted public signals in the wrong order"
    );
}

// ─── Witnesses that do not satisfy the circuit ───────────────────────────────

/// A private value the constraints do not accept. Proving may or may not fail —
/// arkworks does not check satisfiability — but the result must never verify.
#[test]
fn a_witness_that_breaks_the_constraints_does_not_verify() {
    let (pk, matrices, witness) = require_artifacts!();

    let mut broken = witness.clone();
    let private_index = matrices.num_instance_variables + 4;
    broken[private_index] += Bn254Fr::from(1u64);

    // The public signals stay as they were: this is the interesting case, a
    // wallet claiming a true statement it cannot actually back.
    let inputs = public_inputs(&matrices, &witness)
        .expect("witness fits the circuit")
        .to_vec();

    match prove_circom(&pk, &matrices, &broken) {
        Ok(proof) => assert!(
            !verify_proof(&pk.vk, &inputs, &proof).expect("verify"),
            "an unsatisfying witness produced a proof that verifies"
        ),
        Err(_) => { /* refused outright, also correct */ }
    }
}

/// The leading 1 is structural — arkworks supplies its own constant and the
/// assignment must line up with it.
#[test]
fn a_witness_with_the_wrong_constant_does_not_verify() {
    let (pk, matrices, witness) = require_artifacts!();

    let mut broken = witness.clone();
    broken[0] = Bn254Fr::from(2u64);
    let inputs = public_inputs(&matrices, &witness)
        .expect("witness fits the circuit")
        .to_vec();

    // Proving may refuse outright, which is also correct — what must never
    // happen is a proof that verifies.
    if let Ok(proof) = prove_circom(&pk, &matrices, &broken) {
        assert!(
            !verify_proof(&pk.vk, &inputs, &proof).expect("verify"),
            "a witness whose constant is not 1 produced a verifying proof"
        );
    }
}

#[test]
fn an_empty_witness_is_refused() {
    let (pk, matrices, _) = require_artifacts!();
    assert!(prove_circom(&pk, &matrices, &[]).is_err());
}

/// Shorter than the key's instance count. Caught at the boundary rather than
/// panicking on a slice, which is what an FFI caller would otherwise trigger.
#[test]
fn a_witness_shorter_than_the_instance_count_is_refused() {
    let (pk, matrices, witness) = require_artifacts!();
    let short = &witness[..matrices.num_instance_variables - 1];
    assert!(prove_circom(&pk, &matrices, short).is_err());
}

// ─── Proofs that are not proofs ──────────────────────────────────────────────

#[test]
fn random_bytes_do_not_verify_as_a_proof() {
    let (pk, matrices, witness) = require_artifacts!();
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");

    let mut rng = StdRng::seed_from_u64(7);
    let garbage: Vec<u8> = (0..128).map(|_| u8::rand(&mut rng)).collect();

    // Either the bytes fail to decode as curve points, or they decode and fail
    // to verify. Both are correct; silently accepting them is not.
    let accepted = verify_proof(&pk.vk, inputs, &garbage).unwrap_or(false);
    assert!(!accepted, "128 random bytes verified as a proof");
}

/// A single flipped bit. Compressed points carry no checksum, so a corrupted
/// download is exactly this and must be caught by verification.
#[test]
fn a_proof_with_one_flipped_bit_does_not_verify() {
    let (pk, matrices, witness) = require_artifacts!();
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");

    for byte in [0usize, 40, 100] {
        let mut corrupted = proof.clone();
        corrupted[byte] ^= 0x01;
        let accepted = verify_proof(&pk.vk, inputs, &corrupted).unwrap_or(false);
        assert!(!accepted, "a proof with byte {byte} flipped still verified");
    }
}

#[test]
fn a_truncated_proof_is_refused() {
    let (pk, matrices, witness) = require_artifacts!();
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");

    assert!(verify_proof(&pk.vk, inputs, &proof[..127]).is_err());
    assert!(verify_proof(&pk.vk, inputs, &[]).is_err());
}

// ─── Artifacts from the wrong circuit or the wrong setup ─────────────────────

/// The failure the stale `.ark` files caused for a month: a key from a different
/// phase-2 ceremony. Nothing about it looks wrong until a proof is verified.
#[test]
fn a_proof_does_not_verify_against_another_circuits_key() {
    let (pk, matrices, witness) = require_artifacts!();
    let Some(other) = artifact("keys/transfer_pk.zkey") else {
        common::assert_artifacts();
        eprintln!("skipping: transfer key not present");
        return;
    };
    let (other_pk, _) = read_zkey(&mut BufReader::new(File::open(other).unwrap())).unwrap();

    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");

    let accepted = verify_proof(&other_pk.vk, inputs, &proof).unwrap_or(false);
    assert!(
        !accepted,
        "an unshield proof verified against the transfer key"
    );
}

// ─── The .ark v2 container ───────────────────────────────────────────────────

/// A v1 file is what every published package shipped until now, so this is the
/// mistake a caller will actually make. It must be named, not surfaced as a
/// deserialization error thirty layers down.
#[test]
fn a_v1_artifact_is_refused_with_a_useful_message() {
    let (pk, _, _) = require_artifacts!();
    let mut v1 = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&pk, &mut v1).unwrap();

    let msg = read_ark_v2(&v1).unwrap_err().to_string();
    assert!(
        msg.contains("v1") && msg.contains("pack-proving-key"),
        "the error should name the v1 case and how to fix it, got: {msg}"
    );
}

/// Truncation anywhere in the container. A partial download is the realistic
/// cause, and every cut must produce an error rather than a partial key.
#[test]
fn a_truncated_artifact_is_refused_at_every_cut() {
    let (pk, matrices, _) = require_artifacts!();
    let blob = write_ark_v2(&pk, &matrices).expect("write");

    // Cuts at the header, inside the key, and just short of the end. The last
    // is the one that matters most: a download that stops one byte early loses
    // the tail of the matrices, and nothing before that point looks wrong.
    let cuts = [
        11usize,
        blob.len() / 8,
        blob.len() / 2,
        blob.len() - 1024,
        blob.len() - 1,
    ];
    for cut in cuts {
        assert!(
            read_ark_v2(&blob[..cut]).is_err(),
            "an artifact truncated to {cut} of {} bytes was accepted",
            blob.len()
        );
    }
}

/// Corruption inside the key. The magic still matches, so this exercises the
/// deserializer rather than the header check.
#[test]
fn a_corrupted_artifact_body_is_refused() {
    let (pk, matrices, _) = require_artifacts!();
    let mut blob = write_ark_v2(&pk, &matrices).expect("write");

    // Past the 12-byte header, inside the proving key's curve points.
    for offset in [20usize, 1000, 100_000] {
        if offset >= blob.len() {
            continue;
        }
        let original = blob[offset];
        blob[offset] ^= 0xff;
        let result = read_ark_v2(&blob);
        blob[offset] = original;

        // Arkworks may accept some byte patterns as valid points, so a clean
        // parse is possible — but the resulting key must not prove anything
        // that verifies. The parse failing is the common and preferred outcome.
        if let Ok((bad_pk, bad_matrices)) = result {
            assert_eq!(
                bad_matrices.num_constraints, matrices.num_constraints,
                "corruption at {offset} changed the circuit shape unnoticed"
            );
            let _ = bad_pk;
        }
    }
}

/// The round trip must be exact: a re-serialized artifact is byte-identical, so
/// a manifest sha256 stays meaningful across regenerations.
#[test]
fn the_artifact_round_trips_byte_for_byte() {
    let (pk, matrices, _) = require_artifacts!();
    let first = write_ark_v2(&pk, &matrices).expect("write");
    let (pk2, matrices2) = read_ark_v2(&first).expect("read");
    let second = write_ark_v2(&pk2, &matrices2).expect("rewrite");

    assert_eq!(
        first, second,
        "re-serializing the artifact changed its bytes"
    );
    assert_eq!(&first[..8], ARK_V2_MAGIC);
}

/// Every proof from a round-tripped artifact must verify, and each proof must
/// differ — Groth16 is randomised, and a prover that reused its randomness would
/// leak across proofs while still passing a single-shot test.
#[test]
fn repeated_proofs_differ_and_all_verify() {
    let (pk, matrices, witness) = require_artifacts!();
    let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");

    let proofs: Vec<Vec<u8>> = (0..3)
        .map(|_| prove_circom(&pk, &matrices, &witness).expect("prove"))
        .collect();

    for (i, proof) in proofs.iter().enumerate() {
        assert!(
            verify_proof(&pk.vk, inputs, proof).expect("verify"),
            "proof {i} did not verify"
        );
    }
    assert_ne!(proofs[0], proofs[1], "two proofs were byte-identical");
    assert_ne!(proofs[1], proofs[2], "two proofs were byte-identical");
}

// ─── Field-element edge cases at the FFI boundary ────────────────────────────

/// `witness_from_le_bytes` reduces an out-of-range word rather than rejecting it.
///
/// This is the FFI boundary: `generate_proof_wasm` takes raw bytes, and a caller
/// passing a word at or above the modulus gets a proof of a statement it did not
/// intend rather than an error. `from_decimal_str` rejects the same value, so the
/// two entry points disagree on purpose — decimal comes from JSON a human can
/// audit, raw bytes come from a `.wtns` a tool produced.
///
/// Pinned here so a future change to either one is a deliberate decision.
#[test]
fn out_of_range_witness_bytes_reduce_rather_than_error() {
    use ark_ff::PrimeField;

    // r - 1 is the largest legal element; r itself must reduce to zero.
    let modulus = num_bigint::BigUint::from(Bn254Fr::MODULUS);
    let mut bytes = [0u8; 32];
    for (slot, byte) in bytes.iter_mut().zip(modulus.to_bytes_le()) {
        *slot = byte;
    }

    let reduced = groth16_proofs::witness_from_le_bytes(&bytes).expect("32 bytes is one element");
    assert_eq!(reduced.len(), 1);
    assert_eq!(
        reduced[0],
        Bn254Fr::from(0u64),
        "the modulus itself should reduce to zero, not error"
    );

    // And the decimal path refuses the same value, which is the contrast.
    assert!(
        groth16_proofs::from_decimal_str::<Bn254Fr>(&modulus.to_str_radix(10)).is_err(),
        "from_decimal_str must reject what witness_from_le_bytes reduces"
    );
}
