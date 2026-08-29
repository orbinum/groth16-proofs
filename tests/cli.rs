//! The binaries, exercised the way a release pipeline uses them.
//!
//! `pack-proving-key` is what `circuits` calls to produce a published artifact, and
//! `verify-proof` is what turns a spike measurement into evidence. Neither had a
//! test: the crate's suite covers the library and stops at the boundary, which is
//! exactly where a release breaks — a converter that writes a subtly wrong file
//! fails only when someone tries to prove with it, weeks later and somewhere else.
//!
//! Needs the sibling `circuits` artifacts; skips cleanly without them.

mod common;

use common::{artifact, scratch};
use std::path::PathBuf;
use std::process::Command;

/// The binary under test, from the same profile as this test run.
fn bin(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().expect("test binary path");
    p.pop(); // the deps/ directory
    p.pop();
    p.join(name)
}

#[test]
fn pack_proving_key_produces_an_artifact_that_proves() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let out = scratch("convert.ark");
    let _ = std::fs::remove_file(&out);

    let status = Command::new(bin("pack-proving-key"))
        .arg(&zkey)
        .arg(&out)
        .status()
        .expect("run pack-proving-key");
    assert!(status.success(), "pack-proving-key exited with {status}");

    // Not just "a file appeared": the file has to be the thing it claims to be,
    // and has to work. Reading it back is the only check that says so.
    let bytes = std::fs::read(&out).expect("read output");
    assert_eq!(&bytes[..8], groth16_proofs::ARK_V2_MAGIC);
    let (pk, matrices) = groth16_proofs::read_ark_v2(&bytes).expect("read back");
    assert_eq!(
        matrices.num_instance_variables, 8,
        "unshield has 7 public signals plus the constant"
    );
    assert_eq!(matrices.num_constraints, 16_903);
    assert_eq!(pk.vk.gamma_abc_g1.len(), 8);

    let _ = std::fs::remove_file(&out);
}

#[test]
fn pack_proving_key_defaults_the_output_extension() {
    let zkey = require!(artifact("keys/value_proof_pk.zkey"));

    // Copy in, so the derived .ark lands in scratch rather than beside the real
    // keys where it would overwrite a published artifact.
    let copy = scratch("default-ext_pk.zkey");
    std::fs::copy(&zkey, &copy).expect("copy zkey");
    let expected = copy.with_extension("ark");
    let _ = std::fs::remove_file(&expected);

    let status = Command::new(bin("pack-proving-key"))
        .arg(&copy)
        .status()
        .expect("run pack-proving-key");
    assert!(status.success());
    assert!(expected.exists(), "no .ark written next to the .zkey");

    let _ = std::fs::remove_file(&copy);
    let _ = std::fs::remove_file(&expected);
}

#[test]
fn pack_proving_key_fails_on_a_missing_input() {
    let status = Command::new(bin("pack-proving-key"))
        .arg("/nonexistent/nowhere.zkey")
        .arg(scratch("never-written.ark"))
        .status()
        .expect("run pack-proving-key");
    assert!(
        !status.success(),
        "converting a missing file reported success"
    );
}

#[test]
fn pack_proving_key_rejects_a_file_that_is_not_a_zkey() {
    let junk = scratch("not-a-zkey.zkey");
    std::fs::write(&junk, b"this is not a proving key").expect("write junk");

    let status = Command::new(bin("pack-proving-key"))
        .arg(&junk)
        .arg(scratch("never-written-2.ark"))
        .status()
        .expect("run pack-proving-key");
    assert!(!status.success(), "converting junk reported success");

    let _ = std::fs::remove_file(&junk);
}

#[test]
fn verify_proof_accepts_a_real_proof_and_rejects_a_tampered_one() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let wit = require!(artifact("fixtures/unshield.witness.json"));
    let vk_json = require!(artifact("build/verification_key_unshield.json"));

    // The VK the binary takes is the arkworks-compressed form, which pack-verifying-key
    // produces — so this exercises both binaries in the order a release uses them.
    let vk_bin = scratch("verify.vk.bin");
    let status = Command::new(bin("pack-verifying-key"))
        .arg(&vk_json)
        .arg(&vk_bin)
        .status()
        .expect("run pack-verifying-key");
    assert!(status.success(), "pack-verifying-key failed");

    // Prove through the library: no binary produces proofs any more, since the
    // one that did used the wrong reduction and was removed in 3.1.0.
    use std::fs::File;
    use std::io::BufReader;
    let (pk, matrices) =
        groth16_proofs::read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&wit).unwrap()).unwrap();
    let witness: Vec<ark_bn254::Fr> = json["witness"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| groth16_proofs::from_decimal_str::<ark_bn254::Fr>(v.as_str().unwrap()).unwrap())
        .collect();
    let proof = groth16_proofs::prove_circom(&pk, &matrices, &witness).expect("prove");

    let proof_path = scratch("verify.proof.bin");
    std::fs::write(&proof_path, &proof).expect("write proof");

    let status = Command::new(bin("verify-proof"))
        .arg(&proof_path)
        .arg(&vk_bin)
        .arg(&wit)
        .status()
        .expect("run verify-proof");
    assert!(status.success(), "verify-proof rejected a valid proof");

    // The other half. Without it, this test would pass against a binary that
    // exits 0 unconditionally — which is precisely the failure mode that let the
    // QAP bug survive.
    let mut tampered = proof.clone();
    tampered[0] ^= 0x01;
    let tampered_path = scratch("verify.tampered.bin");
    std::fs::write(&tampered_path, &tampered).expect("write tampered");

    let status = Command::new(bin("verify-proof"))
        .arg(&tampered_path)
        .arg(&vk_bin)
        .arg(&wit)
        .status()
        .expect("run verify-proof");
    assert!(!status.success(), "verify-proof accepted a corrupted proof");

    for p in [&vk_bin, &proof_path, &tampered_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn verify_proof_rejects_a_proof_of_the_wrong_length() {
    let wit = require!(artifact("fixtures/unshield.witness.json"));
    let vk_json = require!(artifact("build/verification_key_unshield.json"));

    let vk_bin = scratch("wrong-len.vk.bin");
    let status = Command::new(bin("pack-verifying-key"))
        .arg(&vk_json)
        .arg(&vk_bin)
        .status()
        .expect("run pack-verifying-key");
    assert!(status.success());

    let short = scratch("wrong-len.proof.bin");
    std::fs::write(&short, [0u8; 64]).expect("write short proof");

    let status = Command::new(bin("verify-proof"))
        .arg(&short)
        .arg(&vk_bin)
        .arg(&wit)
        .status()
        .expect("run verify-proof");
    assert!(!status.success(), "a 64-byte proof was accepted");

    let _ = std::fs::remove_file(&vk_bin);
    let _ = std::fs::remove_file(&short);
}

#[test]
fn bench_circom_reports_verified_proofs() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let wit = require!(artifact("fixtures/unshield.witness.json"));

    let out = Command::new(bin("bench-circom"))
        .args(["unshield"])
        .arg(&wit)
        .arg(&zkey)
        .arg("2")
        .output()
        .expect("run bench-circom");
    assert!(
        out.status.success(),
        "bench-circom exited with {}",
        out.status
    );

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("bench-circom stdout is not JSON");

    // The field that matters. A benchmark reporting timings for proofs it never
    // verified is the reason the old one read 48 ms.
    assert_eq!(json["all_verified"], serde_json::Value::Bool(true));
    assert_eq!(json["proof_bytes"], 128);
    assert_eq!(json["num_public"], 7);
    assert_eq!(json["num_witness"], 16_928);
    assert!(json["prove_ms_avg"].as_f64().unwrap() > 0.0);
}
