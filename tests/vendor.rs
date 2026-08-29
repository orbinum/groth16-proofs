//! The vendored ark-circom code, pinned against the upstream it came from.
//!
//! `src/vendor/` is a copy, and copies drift: upstream fixes a bug, or our copy
//! picks up an edit that was meant to be temporary, and nothing notices because
//! nothing compares them. These tests pin the behaviour that made the code worth
//! vendoring, so a divergence shows up as a failure rather than as a proof that
//! quietly stops verifying.
//!
//! Two files, pinned two ways, because they diverge for different reasons.
//! `qap.rs` is byte-identical to upstream and must stay that way — it is the QAP
//! reduction, and an edit there is invisible until proofs stop verifying. It is
//! pinned by content digest. `zkey.rs` diverges deliberately: upstream aborts on
//! malformed input in six places, so each fix is marked in place and the marks
//! are what get counted.
//!
//! They also serve as the regression suite the upstream tests would have given
//! us: `zkey.rs` shipped with a `#[cfg(test)]` module that had to be dropped
//! (it was the only thing referencing wasmer, and its fixtures are not in the
//! published crate).

mod common;

use common::artifact;
use groth16_proofs::read_zkey;
use std::fs::File;
use std::io::BufReader;

/// `read_zkey` must report the circuit's real shape. Every downstream check —
/// the public-signal count, the witness length, the artifact's own header —
/// derives from these numbers, so an off-by-one here is invisible until a proof
/// fails to verify.
#[test]
fn read_zkey_reports_the_unshield_circuits_true_shape() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();

    // Cross-checked against the .r1cs header: nWires 16928, nPubIn 7,
    // nConstraints 16903.
    assert_eq!(matrices.num_constraints, 16_903);
    assert_eq!(
        matrices.num_instance_variables, 8,
        "7 public signals plus the constant"
    );
    assert_eq!(
        pk.vk.gamma_abc_g1.len(),
        8,
        "one IC element per instance variable"
    );
    assert_eq!(pk.a_query.len(), 16_928, "a_query has one entry per wire");

    // l_query covers the private assignment: wires minus instance variables.
    assert_eq!(pk.l_query.len(), 16_928 - 8);
}

/// The C matrix arrives empty, and that is correct rather than a truncated read.
///
/// `CircomReduction` computes C from the A and B evaluations, so upstream does
/// not populate it. Anyone auditing the vendored code will notice the empty
/// vector and reach for a "fix"; this says why not.
#[test]
fn read_zkey_returns_an_empty_c_matrix_by_design() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let (_, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();

    assert!(!matrices.a.is_empty(), "A must be populated");
    assert!(!matrices.b.is_empty(), "B must be populated");
    assert!(
        matrices.c.is_empty(),
        "C is derived by CircomReduction, not read from the zkey"
    );
    assert_eq!(matrices.c_num_non_zero, 0);

    // A and B have one row per constraint even where a row is all zeroes.
    assert_eq!(matrices.a.len(), matrices.num_constraints);
    assert_eq!(matrices.b.len(), matrices.num_constraints);
}

/// The verifying key inside the proving key must be the one the chain has
/// registered. This is the check that would have caught the month the `.ark`
/// files were a different ceremony from their `.zkey`.
#[test]
fn the_embedded_verifying_key_matches_the_published_one() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let vk_json = require!(artifact("build/verification_key_unshield.json"));

    let (pk, _) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();
    let published: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vk_json).unwrap()).unwrap();

    assert_eq!(
        published["nPublic"].as_u64().unwrap() as usize,
        pk.vk.gamma_abc_g1.len() - 1,
        "the zkey and the published VK disagree on the public-signal count"
    );
    assert_eq!(
        published["IC"].as_array().unwrap().len(),
        pk.vk.gamma_abc_g1.len(),
        "the zkey and the published VK disagree on the IC length"
    );
}

/// Reading the same file twice must give the same thing. `read_zkey` walks a
/// section table with a stateful cursor, which is exactly the shape of code that
/// works once and returns something subtly different on a second pass.
#[test]
fn read_zkey_is_deterministic() {
    let zkey = require!(artifact("keys/value_proof_pk.zkey"));

    let (pk1, m1) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    let (pk2, m2) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();

    assert_eq!(m1.num_constraints, m2.num_constraints);
    assert_eq!(m1.num_instance_variables, m2.num_instance_variables);
    assert_eq!(m1.a.len(), m2.a.len());
    assert_eq!(pk1.a_query, pk2.a_query);
    assert_eq!(pk1.vk.gamma_abc_g1, pk2.vk.gamma_abc_g1);
}

/// A file that is not a zkey must be refused rather than parsed into nonsense.
#[test]
fn read_zkey_rejects_a_file_that_is_not_a_zkey() {
    let junk = std::env::temp_dir().join("groth16-proofs-vendor-junk.zkey");
    std::fs::write(&junk, b"not a zkey, just some bytes").unwrap();

    let result = read_zkey(&mut BufReader::new(File::open(&junk).unwrap()));
    assert!(result.is_err(), "junk parsed as a proving key");

    let _ = std::fs::remove_file(&junk);
}

/// All three circuits, so a shape assumption baked in from unshield alone shows
/// up here rather than the first time another circuit is proved.
#[test]
fn every_published_circuit_reads_consistently() {
    // `common::ARITIES` rather than a fourth copy of the table: the point of this
    // test is that the zkey agrees with an independent source, and a source
    // re-inlined here would not be independent of anything.
    for &(name, expected_public) in common::ARITIES {
        let Some(zkey) = artifact(&format!("keys/{name}_pk.zkey")) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: not present");
            continue;
        };
        let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();

        assert_eq!(
            matrices.num_instance_variables - 1,
            expected_public,
            "{name} has the wrong public-signal count"
        );
        assert_eq!(
            pk.vk.gamma_abc_g1.len(),
            expected_public + 1,
            "{name}: IC length does not match the instance count"
        );
        assert_eq!(
            matrices.a.len(),
            matrices.num_constraints,
            "{name}: A is the wrong height"
        );
        assert!(matrices.c.is_empty(), "{name}: C should be empty");
    }
}

/// `qap.rs` still matches the ark-circom 0.5.0 it was copied from.
///
/// This is the check the module header promises and did not perform. It matters
/// most for this file: `CircomReduction` is what makes a proof verify against
/// Circom rather than against arkworks' own convention, and getting it wrong is
/// invisible — the proof is well-formed, exactly 128 bytes, and simply never
/// verifies. That bug shipped twice before anyone noticed.
///
/// Pinned by content hash rather than by diffing against the registry, so the
/// test does not depend on ark-circom being vendored into the developer's
/// `~/.cargo`. The four-line attribution header is skipped; everything below it
/// must be byte-identical.
///
/// If this fails, either upstream was re-vendored (update the hash, and say why
/// in the commit) or someone edited the reduction (do not update the hash).
#[test]
fn the_vendored_qap_reduction_matches_upstream() {
    use blake2::{digest::consts::U32, Blake2b, Digest};

    const HEADER_LINES: usize = 4;
    // blake2b-256 of the file below the header, taken when it was verified
    // byte-identical to ark-circom 0.5.0's src/circom/qap.rs.
    const UPSTREAM_DIGEST: &str =
        "7670318aee33d3558076857cc0b843c9ea5e5ca40883c8972a656c69fc3ef63a";

    let source = include_str!("../src/vendor/qap.rs");
    let body: String = source
        .split_inclusive('\n')
        .skip(HEADER_LINES)
        .collect::<Vec<_>>()
        .concat();

    let actual = hex::encode(Blake2b::<U32>::digest(body.as_bytes()));
    assert_eq!(
        actual, UPSTREAM_DIGEST,
        "src/vendor/qap.rs has diverged from ark-circom 0.5.0. This file is the QAP \
         reduction: an edit here produces proofs that are well-formed and never verify."
    );

    // The header is a comment block, not code — if it grows, the skip is wrong.
    for line in source.lines().take(HEADER_LINES) {
        assert!(
            line.is_empty() || line.starts_with("//"),
            "line {line:?} is not part of the attribution header — HEADER_LINES is stale"
        );
    }
}

/// `zkey.rs` diverges from upstream deliberately, and every divergence is marked.
///
/// Unlike `qap.rs`, this file is not byte-identical: upstream aborts on malformed
/// input in six places, and a `.zkey` is a large binary format from outside this
/// crate. Measured before the hardening: flipping one byte at 30 positions in a
/// real `.zkey` aborted 27 times, because upstream's point constructors use
/// `Affine::new`, which asserts `is_on_curve()` in release builds.
///
/// Since the copy can no longer be compared wholesale, this pins the marks. A
/// re-vendor that silently reverts them would drop the count.
#[test]
fn every_zkey_divergence_is_marked() {
    let source = include_str!("../src/vendor/zkey.rs");
    let marks = source.matches("DIVERGENCE").count();

    // Exactly six, not "at least": a lower bound would pass if the hardening were
    // reverted and only the comments left behind, and an upper bound catches a
    // seventh divergence sneaking in unremarked. Change the number deliberately.
    assert_eq!(
        marks, 6,
        "src/vendor/zkey.rs has {marks} DIVERGENCE marks, expected 6. Either the \
         hardening that keeps a malformed .zkey from aborting was reverted, or a new \
         divergence was added — update this count and say why in the commit."
    );
}
