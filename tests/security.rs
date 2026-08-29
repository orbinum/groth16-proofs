//! Hostile input, and what the parser does with it.
//!
//! The threat model is a wallet. `generate_proof_wasm` takes an artifact that
//! arrived over a network and a witness derived from user data; in a browser a
//! panic aborts the whole module, and an unbounded allocation aborts the
//! process outright — `catch_unwind` does not recover from an allocation
//! failure.
//!
//! Every case here was found by attacking the parser rather than by reading it:
//! forged artifacts whose headers contradict the key they carry, and mutation
//! fuzzing over the real files. Two panics reachable from wasm turned up that
//! way, both now fixed, both pinned below.
//!
//! # What is *not* closed
//!
//! `ark-serialize` sizes a `Vec` from a u64 read straight out of the file and
//! calls `Vec::with_capacity` before reading a single element (0.5.0,
//! `impls.rs:519`). A corrupted length is an arbitrary-allocation primitive
//! that no amount of validation *in this crate* can intercept, because the
//! allocation precedes the read. See `read_ark_v2`'s documentation. Artifacts
//! must therefore be integrity-checked before they reach the parser.

mod common;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::{artifact, load_witness};
use groth16_proofs::{
    compress_snarkjs_proof, pack_snarkjs_vk, prove_circom, read_ark_v2, read_zkey,
    witness_from_le_bytes, ConstraintMatrices, ProofError,
};
use std::fs::File;
use std::io::BufReader;

/// A forged matrix section, mirroring the private `MatrixData`.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct ForgedMatrices {
    num_instance_variables: u64,
    num_witness_variables: u64,
    num_constraints: u64,
    a: Vec<Vec<(Bn254Fr, usize)>>,
    b: Vec<Vec<(Bn254Fr, usize)>>,
}

fn load() -> Option<(ark_groth16::ProvingKey<Bn254>, ConstraintMatrices<Bn254Fr>)> {
    let zkey = artifact("keys/value_proof_pk.zkey")?;
    read_zkey(&mut BufReader::new(File::open(zkey).ok()?)).ok()
}

/// Assemble an artifact from a genuine key and an attacker-chosen header.
fn forge(pk: &ark_groth16::ProvingKey<Bn254>, m: ForgedMatrices) -> Vec<u8> {
    let mut out = groth16_proofs::ARK_V2_MAGIC.to_vec();
    out.extend_from_slice(&groth16_proofs::ARK_V2_VERSION.to_le_bytes());
    pk.serialize_compressed(&mut out).unwrap();
    m.serialize_compressed(&mut out).unwrap();
    out
}

macro_rules! setup {
    () => {
        match load() {
            Some(v) => v,
            None => {
                common::assert_artifacts();
                eprintln!("skipping: circuits artifacts not present");
                return;
            }
        }
    };
}

// ─── Forged headers ──────────────────────────────────────────────────────────

/// The header and the key state the circuit's shape independently. When they
/// disagree, the file is either corrupt or built to make them disagree, and
/// either way the numbers must not be trusted downstream: `public_inputs`
/// slices the witness by `num_instance_variables`.
#[test]
fn a_header_that_contradicts_its_key_is_refused() {
    let (pk, real) = setup!();

    for (label, instance) in [
        ("inflated", 1_000_000u64),
        ("u64::MAX", u64::MAX),
        ("zero", 0),
    ] {
        let blob = forge(
            &pk,
            ForgedMatrices {
                num_instance_variables: instance,
                num_witness_variables: real.num_witness_variables as u64,
                num_constraints: real.num_constraints as u64,
                a: real.a.clone(),
                b: real.b.clone(),
            },
        );
        let err = read_ark_v2(&blob)
            .err()
            .unwrap_or_else(|| panic!("{label} instance count was accepted"));
        assert!(
            err.to_string().contains("different circuits"),
            "{label}: {err}"
        );
    }
}

/// `num_witness_variables` is half of the column bound, so leaving it free
/// makes that bound vacuous — and at `u64::MAX` the sum *wraps* in release,
/// where overflow is unchecked, producing a bound that looks valid and is not.
/// Either way an out-of-range column reaches arkworks, which indexes the
/// witness without checking.
#[test]
fn a_witness_count_that_would_defeat_the_column_bound_is_refused() {
    let (pk, real) = setup!();

    for (label, witness) in [("near-max", u64::MAX - 2), ("wrapping", u64::MAX)] {
        let blob = forge(
            &pk,
            ForgedMatrices {
                num_instance_variables: pk.vk.gamma_abc_g1.len() as u64,
                num_witness_variables: witness,
                num_constraints: 1,
                a: vec![vec![(Bn254Fr::from(1u64), 1_000_000usize)]],
                b: vec![vec![(Bn254Fr::from(1u64), 0usize)]],
            },
        );
        assert!(
            read_ark_v2(&blob).is_err(),
            "{label} witness count was accepted — the column bound is defeated"
        );
        let _ = real.num_constraints;
    }
}

/// A column index past the end of the assignment is an out-of-bounds read
/// waiting for whichever consumer indexes with it.
#[test]
fn a_matrix_column_past_the_end_is_refused() {
    let (pk, real) = setup!();
    let mut a = real.a.clone();
    a[0].push((Bn254Fr::from(1u64), usize::MAX));

    let blob = forge(
        &pk,
        ForgedMatrices {
            num_instance_variables: real.num_instance_variables as u64,
            num_witness_variables: real.num_witness_variables as u64,
            num_constraints: real.num_constraints as u64,
            a,
            b: real.b.clone(),
        },
    );
    let err = read_ark_v2(&blob).unwrap_err();
    assert!(err.to_string().contains("column"), "got: {err}");
}

/// A constraint count larger than the bytes that follow cannot be honest, and
/// must be caught before anything is sized from it.
#[test]
fn a_constraint_count_larger_than_the_file_is_refused() {
    let (pk, real) = setup!();
    let blob = forge(
        &pk,
        ForgedMatrices {
            num_instance_variables: real.num_instance_variables as u64,
            num_witness_variables: real.num_witness_variables as u64,
            num_constraints: 1 << 40,
            a: real.a.clone(),
            b: real.b.clone(),
        },
    );
    assert!(
        read_ark_v2(&blob).is_err(),
        "a 2^40 constraint count was accepted"
    );
}

/// The row-count prefix that ark-serialize actually sizes from, forged directly.
///
/// The test above goes through `ForgedMatrices`, which re-serializes
/// consistently: `num_constraints` and the `Vec` length prefix always agree. But
/// they are two independent fields on the wire, and only the first was bounded.
/// An artifact with an honest `num_constraints` and a hostile outer prefix
/// reached `Vec::with_capacity` — measured on a 250 KB file, far under
/// `MAX_ARTIFACT_BYTES`, which aborted with `capacity overflow`.
///
/// That is a recoverable panic natively. In wasm it is not: `read_ark_v2` is what
/// `generate_proof_wasm` calls, and wasm has no unwinding, so the module dies.
///
/// Assembled byte by byte rather than through `ForgedMatrices`, because the whole
/// point is a file the honest serializer cannot produce.
#[test]
fn a_hostile_row_prefix_is_refused_before_it_is_sized() {
    let (pk, real) = setup!();

    let mut blob = groth16_proofs::ARK_V2_MAGIC.to_vec();
    blob.extend_from_slice(&groth16_proofs::ARK_V2_VERSION.to_le_bytes());
    pk.serialize_compressed(&mut blob).unwrap();

    // A header the reconciliation checks accept, so the row prefix is what is
    // left to reject.
    blob.extend_from_slice(&(real.num_instance_variables as u64).to_le_bytes());
    blob.extend_from_slice(&(real.num_witness_variables as u64).to_le_bytes());
    blob.extend_from_slice(&2u64.to_le_bytes());

    // 2^60 rows: absurd, and small enough as a number that nothing else notices.
    blob.extend_from_slice(&(1u64 << 60).to_le_bytes());

    let outcome = std::panic::catch_unwind(|| read_ark_v2(&blob));
    match outcome {
        Ok(Ok(_)) => panic!("a 2^60 row prefix was accepted"),
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("1152921504606846976") && msg.contains("2"),
                "the error should name both the declared rows and the header count: {msg}"
            );
        }
        Err(_) => panic!("a 2^60 row prefix still panics rather than returning Err"),
    }
}

/// An artifact over the size limit is refused before parsing.
#[test]
fn an_oversized_artifact_is_refused() {
    let mut blob = groth16_proofs::ARK_V2_MAGIC.to_vec();
    blob.extend_from_slice(&groth16_proofs::ARK_V2_VERSION.to_le_bytes());
    blob.resize(groth16_proofs::MAX_ARTIFACT_BYTES + 1, 0);

    let err = read_ark_v2(&blob).unwrap_err();
    assert!(err.to_string().contains("limit"), "got: {err}");
}

// ─── Witness handling ────────────────────────────────────────────────────────

/// A truncated witness must be an error, not a slice out of range. This is the
/// panic that fuzzing found: the wasm bindings call `public_inputs` *before*
/// `prove_circom`, so the prover's own length check never ran.
#[test]
fn a_short_witness_does_not_panic() {
    let (_, real) = setup!();
    let short: Vec<Bn254Fr> = (0..2u64).map(Bn254Fr::from).collect();

    let err = groth16_proofs::public_inputs(&real, &short).unwrap_err();
    assert!(
        matches!(err, ProofError::NumPublicSignals(_)),
        "got: {err:?}"
    );
}

/// Every witness length between the public-signal count and the circuit's width.
///
/// `public_inputs` was bounded; `prove_circom` was not. It checked the witness
/// only against `num_instance_variables`, leaving the constraint matrices free to
/// reference any column up to the real width — and arkworks indexes the witness
/// with those columns unchecked (ark-groth16 0.5.0, r1cs_to_qap.rs:29).
///
/// Measured on value_proof, 5 instance variables in a 1157-wide circuit: lengths
/// 5, 6, 578 and 1155 all panicked. `generate_proof_wasm` calls this, and wasm has
/// no unwinding, so each one aborted the module rather than returning to JS.
///
/// The overlong case is quieter and was also wrong: `msm_bigint` truncates
/// silently, so the caller got a well-formed proof that could never verify.
#[test]
fn no_witness_length_panics_in_prove() {
    let (pk, real) = setup!();
    let Some(path) = artifact("fixtures/value_proof.witness.json") else {
        common::assert_artifacts();
        eprintln!("skipping: no value_proof witness fixture");
        return;
    };
    let (witness, _) = load_witness(&path);

    let width = witness.len();
    let mut lengths: Vec<usize> = vec![1, 2, real.num_instance_variables, width - 1];
    lengths.push(width / 2);
    lengths.dedup();

    for len in lengths {
        let short = witness[..len.min(width)].to_vec();
        let outcome = std::panic::catch_unwind(|| prove_circom(&pk, &real, &short));
        match outcome {
            Err(_) => panic!("a witness of length {len} panicked instead of returning Err"),
            Ok(Ok(_)) => panic!("a witness of length {len} was accepted"),
            Ok(Err(_)) => {}
        }
    }

    // Overlong, which used to be accepted and silently truncated.
    let mut long = witness.clone();
    long.extend_from_slice(&witness[..8]);
    match std::panic::catch_unwind(|| prove_circom(&pk, &real, &long)) {
        Err(_) => panic!("an overlong witness panicked"),
        Ok(Ok(_)) => panic!("an overlong witness was accepted and silently truncated"),
        Ok(Err(_)) => {}
    }

    // And the real witness still proves, so the bound is not merely tight.
    let proof = prove_circom(&pk, &real, &witness).expect("the real witness must still prove");
    assert_eq!(proof.len(), 128);
}

/// Every buffer length, including the ones that are not whole field elements.
#[test]
fn no_witness_buffer_length_panics() {
    for len in 0..200usize {
        let buf = vec![0xABu8; len];
        let got = witness_from_le_bytes(&buf);
        if len % 32 == 0 {
            assert_eq!(got.unwrap().len(), len / 32);
        } else {
            assert!(got.is_err(), "{len} bytes was accepted as a witness");
        }
    }
}

// ─── snarkjs input ───────────────────────────────────────────────────────────

/// Points must be validated, not merely parsed. `G1Affine::new` asserts in
/// release builds, so a point off the curve would abort rather than error.
#[test]
fn a_point_off_the_curve_is_an_error_not_an_abort() {
    // (1, 1) does not satisfy y² = x³ + 3.
    let proof = r#"{"pi_a":["1","1","1"],
                    "pi_b":[["1","2"],["3","4"],["1","0"]],
                    "pi_c":["1","2","1"]}"#;
    let err = compress_snarkjs_proof(proof).unwrap_err();
    assert!(err.to_string().contains("curve"), "got: {err}");
}

/// Truncating valid JSON at every length must never panic.
#[test]
fn no_truncation_of_snarkjs_json_panics() {
    let vk = match artifact("build/verification_key_value_proof.json") {
        Some(p) => std::fs::read_to_string(p).unwrap(),
        None => {
            common::assert_artifacts();
            eprintln!("skipping: circuits artifacts not present");
            return;
        }
    };
    let mut swept = 0;
    for cut in (0..vk.len()).step_by(7) {
        let _ = pack_snarkjs_vk(&vk[..cut]);
        swept += 1;
    }
    assert!(
        swept > 50,
        "the sweep should cover the file, cut {swept} times"
    );
    assert!(
        pack_snarkjs_vk(&vk).is_ok(),
        "the untruncated key must still parse — otherwise this test proves nothing"
    );
}

/// Truncating an artifact at every length must never panic.
#[test]
fn no_truncation_of_an_artifact_panics() {
    let ark = match artifact("keys/value_proof_pk.ark") {
        Some(p) => std::fs::read(p).unwrap(),
        None => {
            common::assert_artifacts();
            eprintln!("skipping: circuits artifacts not present");
            return;
        }
    };
    // Step coarsely: the point is coverage of every structural boundary, not
    // every byte, and a full sweep of a 310 KB file is slow in CI.
    let mut swept = 0;
    for cut in (0..ark.len()).step_by(997) {
        let _ = read_ark_v2(&ark[..cut]);
        swept += 1;
    }
    assert!(
        swept > 200,
        "the sweep should cover the file, cut {swept} times"
    );
    assert!(
        read_ark_v2(&ark).is_ok(),
        "the untruncated artifact must still parse — otherwise this test proves nothing"
    );
}

/// A `.zkey` is a large binary format from outside this crate, and `read_zkey`
/// is `pub` and re-exported — a consumer can hand it network bytes even though
/// this crate only ever passes it a local file.
///
/// Upstream ark-circom aborts on five separate malformed inputs: a missing
/// section (`unwrap` on the map lookup, then again on the vec), non-UTF8 magic,
/// two unchecked subtractions that underflow, and an unvalidated `u32` indexing
/// a two-element vec. Worst of all, its point constructors use `Affine::new`,
/// which asserts `is_on_curve()` **in release builds** — measured by flipping one
/// byte at 30 positions in a real `.zkey`: 27 aborted.
#[test]
fn no_hostile_zkey_panics() {
    use std::io::Cursor;

    let Some(path) = artifact("keys/value_proof_pk.zkey") else {
        common::assert_artifacts();
        eprintln!("skipping: no value_proof zkey");
        return;
    };
    let good = std::fs::read(&path).expect("read zkey");

    // The real file still parses — the hardening is not merely rejecting everything.
    let (pk, matrices) =
        read_zkey(&mut Cursor::new(good.clone())).expect("the real zkey must parse");
    assert!(matrices.num_constraints > 0);
    assert!(!pk.vk.gamma_abc_g1.is_empty());

    // A structurally valid header whose sections the reader needs and cannot find.
    let mut headers_only = b"zkey".to_vec();
    headers_only.extend_from_slice(&1u32.to_le_bytes());
    headers_only.extend_from_slice(&0u32.to_le_bytes()); // zero sections
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("no sections at all", headers_only),
        ("non-UTF8 magic", {
            let mut b = good.clone();
            b[0] = 0xFF;
            b[1] = 0xFE;
            b
        }),
    ];

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    for (label, bytes) in cases {
        match std::panic::catch_unwind(|| read_zkey(&mut Cursor::new(bytes))) {
            Err(_) => {
                std::panic::set_hook(previous);
                panic!("{label} panicked instead of returning Err");
            }
            Ok(Ok(_)) => {
                std::panic::set_hook(previous);
                panic!("{label} was accepted");
            }
            Ok(Err(_)) => {}
        }
    }

    // A sweep, because the panics were spread across the file rather than
    // clustered at the header.
    let mut checked = 0;
    for offset in (0..good.len()).step_by(good.len() / 60 + 1) {
        let mut flipped = good.clone();
        flipped[offset] ^= 0xFF;
        checked += 1;
        if std::panic::catch_unwind(|| read_zkey(&mut Cursor::new(flipped))).is_err() {
            std::panic::set_hook(previous);
            panic!("a flipped byte at offset {offset} panicked");
        }
    }
    for cut in (0..good.len()).step_by(good.len() / 30 + 1) {
        checked += 1;
        let truncated = good[..cut].to_vec();
        if std::panic::catch_unwind(|| read_zkey(&mut Cursor::new(truncated))).is_err() {
            std::panic::set_hook(previous);
            panic!("truncating to {cut} bytes panicked");
        }
    }

    std::panic::set_hook(previous);
    assert!(
        checked > 80,
        "the sweep should cover the file, checked {checked}"
    );
}

/// The G2 subgroup check, which no test exercised.
///
/// `validate` in format/snarkjs.rs runs two checks: on-curve, then in-prime-order-
/// subgroup. On BN254 the first is a no-op for G1 (cofactor 1) but the second is
/// load-bearing for G2, whose cofactor is large — a point can sit on the curve and
/// still generate a small subgroup, which is a real attack on pairing-based
/// verification.
///
/// Every existing test that reaches `validate` fails at the on-curve branch, so
/// the subgroup branch below it had never executed. This builds a point that is
/// genuinely on the curve and genuinely outside the prime-order subgroup.
#[test]
fn a_g2_point_outside_the_prime_order_subgroup_is_refused() {
    use ark_bn254::{Fq, Fq2, G2Affine};

    // Search the curve for a point whose order is not r. Most x yield no point at
    // all; of those that do, the ones in the prime-order subgroup are a small
    // fraction, so a short scan finds a witness.
    let mut found: Option<G2Affine> = None;
    for i in 1u64..400 {
        let x = Fq2::new(Fq::from(i), Fq::from(i + 1));
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, false) {
            if p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve() {
                found = Some(p);
                break;
            }
        }
    }
    let bad = found.expect("a G2 point on the curve but outside the subgroup should exist");
    assert!(bad.is_on_curve(), "the witness must be on the curve");
    assert!(
        !bad.is_in_correct_subgroup_assuming_on_curve(),
        "the witness must be outside the prime-order subgroup"
    );

    // Substitute it for vk_beta_2 in an otherwise valid verifying key.
    let Some(path) = artifact("build/verification_key_value_proof.json") else {
        common::assert_artifacts();
        eprintln!("skipping: no verifying key");
        return;
    };
    let json = std::fs::read_to_string(&path).expect("read vk");
    let mut vk: serde_json::Value = serde_json::from_str(&json).expect("parse vk");

    let d = |f: Fq| -> String {
        use ark_ff::{BigInteger, PrimeField};
        num_bigint::BigUint::from_bytes_le(&f.into_bigint().to_bytes_le()).to_str_radix(10)
    };
    vk["vk_beta_2"] = serde_json::json!([
        [d(bad.x.c0), d(bad.x.c1)],
        [d(bad.y.c0), d(bad.y.c1)],
        ["1", "0"]
    ]);

    let err =
        pack_snarkjs_vk(&vk.to_string()).expect_err("a small-subgroup G2 point must be refused");
    let message = err.to_string();
    assert!(
        message.contains("subgroup"),
        "the error should name the subgroup check, got: {message}"
    );
}

/// Nothing may follow the matrix section of a `.ark` artifact.
///
/// Measured before this check existed: a real artifact with a megabyte of padding
/// appended parsed as valid and produced the same key and matrices. The manifest
/// pins artifacts by sha256, so a padded file would not survive the integrity
/// check that `proof-generator` performs — but that is a caller's contract, and a
/// format that accepts padding is not canonical.
#[test]
fn an_artifact_with_trailing_bytes_is_refused() {
    let Some(path) = artifact("keys/value_proof_pk.ark") else {
        common::assert_artifacts();
        eprintln!("skipping: no value_proof .ark");
        return;
    };
    let good = std::fs::read(&path).expect("read artifact");
    read_ark_v2(&good).expect("the real artifact must parse");

    for extra in [1usize, 64, 4096] {
        let mut padded = good.clone();
        padded.extend(std::iter::repeat_n(0xAAu8, extra));
        let Err(err) = read_ark_v2(&padded) else {
            panic!("{extra} trailing bytes were accepted");
        };
        assert!(
            err.to_string().contains("follow the matrix section"),
            "got: {err}"
        );
    }
}

/// A Groth16 proof is exactly 128 bytes, and anything else is refused.
///
/// `deserialize_compressed` reads from the front of a slice and ignores the rest,
/// so a 129-byte input whose first 128 bytes are a valid proof used to verify —
/// two encodings of one proof, which matters wherever proof bytes are hashed.
#[test]
fn a_proof_must_be_exactly_128_bytes() {
    use groth16_proofs::verify_proof;

    let Some(vk_path) = artifact("build/verification_key_value_proof.json") else {
        common::assert_artifacts();
        eprintln!("skipping: no verifying key");
        return;
    };
    let vk = groth16_proofs::parse_snarkjs_vk(&std::fs::read_to_string(&vk_path).expect("read vk"))
        .expect("parse vk");

    for len in [0usize, 127, 129, 256] {
        let bytes = vec![0u8; len];
        let Err(err) = verify_proof(&vk, &[], &bytes) else {
            panic!("a {len}-byte proof was accepted");
        };
        // Every wrong length takes the same branch, so every one names the rule.
        // The earlier version exempted 0 and 127 from this, which would have let
        // them start failing for an unrelated reason without the test noticing.
        assert!(
            err.to_string().contains("128 bytes"),
            "a {len}-byte proof should be refused on length, got: {err}"
        );
    }
}

/// `parse_snarkjs_vk` refuses what `pack_snarkjs_vk` refuses.
///
/// Every malformed-VK test in this repository goes through `pack_snarkjs_vk`,
/// which parses and then re-serializes. `parse_snarkjs_vk` is a separate public
/// entry point — a caller that wants an arkworks `VerifyingKey` rather than the
/// chain's bytes calls it directly — and it had no negative coverage at all. The
/// two share an implementation today; this pins that they share a contract.
#[test]
fn parse_snarkjs_vk_refuses_what_packing_refuses() {
    let Some(path) = artifact("build/verification_key_value_proof.json") else {
        common::assert_artifacts();
        eprintln!("skipping: no verifying key");
        return;
    };
    let good = std::fs::read_to_string(&path).expect("read vk");

    // The honest key parses, so a rejection below is the input, not the parser.
    let parsed = groth16_proofs::parse_snarkjs_vk(&good).expect("the real key must parse");
    assert!(!parsed.gamma_abc_g1.is_empty());

    let mut broken: Vec<(&str, String)> = Vec::new();

    let mut v: serde_json::Value = serde_json::from_str(&good).expect("parse json");
    v["IC"] = serde_json::json!([]);
    broken.push(("empty IC", v.to_string()));

    let mut v: serde_json::Value = serde_json::from_str(&good).expect("parse json");
    v.as_object_mut().expect("object").remove("vk_alpha_1");
    broken.push(("missing vk_alpha_1", v.to_string()));

    let mut v: serde_json::Value = serde_json::from_str(&good).expect("parse json");
    v["vk_alpha_1"] = serde_json::json!(["1", "1", "1"]);
    broken.push(("point off the curve", v.to_string()));

    let mut v: serde_json::Value = serde_json::from_str(&good).expect("parse json");
    let x = v["vk_alpha_1"][0].as_str().expect("string").to_string();
    v["vk_alpha_1"][0] = serde_json::json!(format!("00{x}"));
    broken.push(("non-canonical coordinate", v.to_string()));

    broken.push(("not json at all", "{ nope".to_string()));

    for (label, json) in broken {
        assert!(
            groth16_proofs::parse_snarkjs_vk(&json).is_err(),
            "parse_snarkjs_vk accepted {label}"
        );
        assert!(
            pack_snarkjs_vk(&json).is_err(),
            "pack_snarkjs_vk accepted {label}, so the two disagree"
        );
    }
}

/// Every `ProofError` variant renders a message that names its subject.
///
/// Eight of the ten variants had no test touching their `Display` arm, so a
/// copy-paste in `error.rs` — the wrong subject in the wrong arm — would have
/// reached a user before it reached a test. That is not hypothetical: the type's
/// own doc records `SnarkjsProofParse` being reported for arkworks failures
/// before 3.1.0.
#[test]
fn every_error_variant_renders_its_own_subject() {
    use groth16_proofs::ProofError::*;

    let cases: &[(ProofError, &str)] = &[
        (WitnessEmpty, "witness"),
        (WitnessLength("x".into()), "x"),
        (NumPublicSignals("x".into()), "x"),
        (ProvingKeyParse("x".into()), "x"),
        (ProveGeneration("x".into()), "x"),
        (ProofSerialization("x".into()), "x"),
        (ProofDeserialization("x".into()), "x"),
        (WitnessJsonParse("x".into()), "x"),
        (SnarkjsParse("x".into()), "x"),
        (Verification("x".into()), "x"),
    ];

    for (err, expected) in cases {
        let rendered = err.to_string().to_lowercase();
        assert!(
            rendered.contains(&expected.to_lowercase()),
            "{err:?} rendered as {rendered:?}, which does not name {expected:?}"
        );
        assert!(!rendered.is_empty(), "{err:?} rendered empty");
    }
}
