//! Cross-verification against snarkjs, the independent implementation.
//!
//! Every other test in this crate checks arkworks against itself: prove with
//! arkworks, verify with arkworks. That catches a broken prover, but not a
//! prover and verifier that are wrong in the same direction — and "wrong in the
//! same direction" is precisely what the QAP-reduction bug was, on the other
//! side. `Groth16::prove` and `Groth16::verify` agreed perfectly with each
//! other; they just did not agree with Circom.
//!
//! The chain accepts what snarkjs's verifier accepts. So the question that
//! actually matters before publishing is not "does arkworks verify our proof"
//! but "does snarkjs". These tests answer it in both directions.
//!
//! All three published circuits are covered. Running only unshield would leave
//! a shape assumption baked in from one circuit — value_proof has four public
//! signals where the others have seven, and its first signal is a circuit
//! *output* rather than an input, which is exactly the kind of difference a
//! single-circuit test cannot see.
//!
//! Needs the sibling `circuits` checkout with node_modules installed. Skips
//! cleanly when snarkjs is unavailable, so CI without it stays green.

mod common;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use common::{artifact, load_witness, scratch, ARITIES};
use groth16_proofs::{prove_circom, public_inputs, read_zkey, verify_proof};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Command;

fn snarkjs() -> Option<PathBuf> {
    artifact("node_modules/.bin/snarkjs")
}

/// A field element as the decimal string snarkjs reads and writes.
fn to_decimal(f: &Bn254Fr) -> String {
    f.into_bigint().to_string()
}

/// An arkworks compressed proof as the `{pi_a, pi_b, pi_c}` JSON snarkjs wants.
///
/// The two encodings hold the same points in different shapes: arkworks packs
/// them compressed and little-endian, snarkjs writes affine coordinates as
/// decimal strings with a projective `1` appended. Converting here rather than
/// shelling out keeps the test honest — it is our bytes that snarkjs checks.
fn proof_to_snarkjs_json(proof_bytes: &[u8]) -> String {
    use ark_bn254::Bn254;
    use ark_serialize::CanonicalDeserialize;

    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .expect("deserialize proof");

    let fq = |v: &ark_bn254::Fq| v.into_bigint().to_string();

    format!(
        r#"{{"protocol":"groth16","curve":"bn128",
            "pi_a":["{}","{}","1"],
            "pi_b":[["{}","{}"],["{}","{}"],["1","0"]],
            "pi_c":["{}","{}","1"]}}"#,
        fq(&proof.a.x),
        fq(&proof.a.y),
        fq(&proof.b.x.c0),
        fq(&proof.b.x.c1),
        fq(&proof.b.y.c0),
        fq(&proof.b.y.c1),
        fq(&proof.c.x),
        fq(&proof.c.y),
    )
}

/// **The test that decides whether this crate can ship.**
///
/// An arkworks proof, checked by snarkjs against the same verification key the
/// chain has registered. If this fails, everything else passing means only that
/// we are consistently wrong.
#[test]
fn snarkjs_accepts_the_proofs_this_crate_produces() {
    let snarkjs_bin = require!(snarkjs(), "snarkjs");
    let mut covered = 0;

    for (name, arity) in ARITIES {
        let (Some(zkey), Some(wit), Some(vk)) = (
            artifact(&format!("keys/{name}_pk.zkey")),
            artifact(&format!("fixtures/{name}.witness.json")),
            artifact(&format!("build/verification_key_{name}.json")),
        ) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: artifacts or fixture not present");
            continue;
        };

        let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
        let (witness, _) = load_witness(&wit);

        let proof = prove_circom(&pk, &matrices, &witness).expect("prove");
        let inputs = public_inputs(&matrices, &witness).expect("witness fits the circuit");
        assert_eq!(
            inputs.len(),
            *arity,
            "{name}: proved with the wrong number of public signals"
        );

        // Our own verifier first, so a failure downstream is unambiguous.
        assert!(
            verify_proof(&pk.vk, inputs, &proof).expect("verify"),
            "{name}: arkworks rejected its own proof — the cross-check is moot"
        );

        let proof_path = scratch(&format!("xverify-{name}-proof.json"));
        let public_path = scratch(&format!("xverify-{name}-public.json"));
        std::fs::write(&proof_path, proof_to_snarkjs_json(&proof)).expect("write proof");
        std::fs::write(
            &public_path,
            serde_json::to_string(&inputs.iter().map(to_decimal).collect::<Vec<_>>()).unwrap(),
        )
        .expect("write public");

        let out = Command::new(&snarkjs_bin)
            .args(["groth16", "verify"])
            .arg(&vk)
            .arg(&public_path)
            .arg(&proof_path)
            .output()
            .expect("run snarkjs verify");

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        for p in [&proof_path, &public_path] {
            let _ = std::fs::remove_file(p);
        }

        assert!(
            combined.contains("OK!"),
            "snarkjs rejected a {name} proof from this crate. Output:\n{combined}"
        );
        covered += 1;
    }

    assert!(covered > 0, "no circuit was actually cross-verified");
    eprintln!("cross-verified {covered} circuit(s)");
}

/// The reverse direction: a snarkjs proof checked by this crate's verifier.
///
/// Guards against a verifier that accepts our own output and nothing else,
/// which would pass every test above while being useless for checking anything
/// that arrives from elsewhere.
#[test]
fn this_crate_accepts_the_proofs_snarkjs_produces() {
    let snarkjs_bin = require!(snarkjs(), "snarkjs");
    let mut covered = 0;

    for (name, _) in ARITIES {
        let (Some(zkey), Some(wtns)) = (
            artifact(&format!("keys/{name}_pk.zkey")),
            artifact(&format!("fixtures/{name}.wtns")),
        ) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: artifacts or fixture not present");
            continue;
        };

        let proof_path = scratch(&format!("sj-{name}-proof.json"));
        let public_path = scratch(&format!("sj-{name}-public.json"));

        let out = Command::new(&snarkjs_bin)
            .args(["groth16", "prove"])
            .arg(&zkey)
            .arg(&wtns)
            .arg(&proof_path)
            .arg(&public_path)
            .output()
            .expect("run snarkjs prove");
        assert!(
            out.status.success(),
            "{name}: snarkjs prove failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let proof_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&proof_path).unwrap()).unwrap();
        let public_json: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(&public_path).unwrap()).unwrap();

        // compress_snarkjs_proof is the existing path from snarkjs JSON to the
        // 128-byte on-chain form, so this also pins that conversion.
        let compressed = groth16_proofs::compress_snarkjs_proof(&proof_json.to_string())
            .expect("compress snarkjs proof");
        assert_eq!(compressed.len(), 128);

        let (pk, _) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
        let inputs: Vec<Bn254Fr> = public_json
            .iter()
            .map(|s| groth16_proofs::from_decimal_str::<Bn254Fr>(s).unwrap())
            .collect();

        for p in [&proof_path, &public_path] {
            let _ = std::fs::remove_file(p);
        }

        assert!(
            verify_proof(&pk.vk, &inputs, &compressed).expect("verify"),
            "{name}: this crate rejected a proof snarkjs produced and verified"
        );
        covered += 1;
    }

    assert!(covered > 0, "no circuit was actually checked");
}

/// Both provers, one witness. The public signals must be identical — they come
/// from the same witness — which is what pins the *order* of those signals.
///
/// This is the check that catches a layout disagreement: value_proof's first
/// public signal is a circuit output, not an input, and nothing but a
/// comparison against snarkjs would reveal a prover that assumed otherwise.
#[test]
fn both_provers_agree_on_the_public_signals() {
    let snarkjs_bin = require!(snarkjs(), "snarkjs");
    let mut covered = 0;

    for (name, arity) in ARITIES {
        let (Some(zkey), Some(wtns), Some(wit)) = (
            artifact(&format!("keys/{name}_pk.zkey")),
            artifact(&format!("fixtures/{name}.wtns")),
            artifact(&format!("fixtures/{name}.witness.json")),
        ) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: artifacts or fixture not present");
            continue;
        };

        let proof_path = scratch(&format!("agree-{name}-proof.json"));
        let public_path = scratch(&format!("agree-{name}-public.json"));
        let out = Command::new(&snarkjs_bin)
            .args(["groth16", "prove"])
            .arg(&zkey)
            .arg(&wtns)
            .arg(&proof_path)
            .arg(&public_path)
            .output()
            .expect("run snarkjs prove");
        assert!(out.status.success(), "{name}: snarkjs prove failed");

        let snarkjs_public: Vec<String> =
            serde_json::from_str(&std::fs::read_to_string(&public_path).unwrap()).unwrap();

        let (_, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
        let (witness, _) = load_witness(&wit);
        let ours: Vec<String> = public_inputs(&matrices, &witness)
            .expect("witness fits the circuit")
            .iter()
            .map(to_decimal)
            .collect();

        for p in [&proof_path, &public_path] {
            let _ = std::fs::remove_file(p);
        }

        assert_eq!(ours.len(), *arity, "{name}: wrong number of public signals");
        assert_eq!(
            ours, snarkjs_public,
            "{name}: the two implementations disagree on which values are public, \
             or on their order"
        );
        covered += 1;
    }

    assert!(covered > 0, "no circuit was actually compared");
}
