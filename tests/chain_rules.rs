//! The chain's acceptance rules, replicated and checked against our output.
//!
//! Every other test here checks arkworks against arkworks, or arkworks against
//! snarkjs. Neither answers the question that decides whether a proof is worth
//! anything: **would the chain take it?**
//!
//! The chain's verifier lives in another repository. Depending on it would
//! couple this crate to a Substrate node for what amounts to fifteen lines of
//! validation, so the rules are reproduced here instead, each one annotated
//! with where it comes from. That is sound because the rules are not the node's
//! own arithmetic — they are `ark-groth16` 0.5 plus three bounds checks, and
//! this crate builds against the same `ark-groth16` 0.5. The byte layouts match
//! by construction rather than by assertion.
//!
//! What is *not* guaranteed by construction is that the node's rules stay put.
//! If they change, these tests keep passing while reality diverges — so each
//! one names its source, and the comment is the thing to re-read when the
//! runtime is upgraded.
//!
//! Source: `orbinum-zk-verifier`, `src/types.rs` and `src/verifier.rs`.

mod common;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use common::{artifact, load_witness, ARITIES};
use groth16_proofs::{
    field_to_le_hex, pack_snarkjs_vk, prove_circom, public_inputs, read_zkey, verify_proof,
};
use std::fs::File;
use std::io::BufReader;

// ─── The chain's constants ───────────────────────────────────────────────────

/// `MAX_PROOF_BYTES` — types.rs. A compressed BN254 proof is 128; the bound is
/// a ceiling on what the runtime will even attempt to deserialize.
const MAX_PROOF_BYTES: usize = 1024;

/// `MAX_VK_BYTES` — types.rs.
const MAX_VK_BYTES: usize = 8192;

/// `MAX_PUBLIC_INPUTS` — types.rs.
const MAX_PUBLIC_INPUTS: usize = 32;

// ─── The rules ───────────────────────────────────────────────────────────────

/// The chain's public-input rule, transcribed from `types.rs::to_field_elements`:
///
/// ```ignore
/// let fe = Bn254Fr::from_le_bytes_mod_order(bytes);
/// if fe.into_bigint().to_bytes_le().as_slice() != &bytes[..] {
///     return Err(VerifierError::InvalidPublicInput);
/// }
/// ```
///
/// Reduction alone is not enough: the encoding must reproduce itself. `n` and
/// `n + p` are the same field element and only the first is accepted, so this
/// is a rule about bytes, not about values.
fn chain_accepts_public_input(bytes: &[u8; 32]) -> bool {
    let fe = Bn254Fr::from_le_bytes_mod_order(bytes);
    fe.into_bigint().to_bytes_le().as_slice() == &bytes[..]
}

/// Decode the hex `field_to_le_hex` produces back into the 32 bytes the chain
/// would receive.
fn hex_to_le_bytes(hex: &str) -> [u8; 32] {
    let raw = hex::decode(hex.trim_start_matches("0x")).expect("valid hex");
    raw.try_into().expect("32 bytes")
}

// ─── Public-signal encoding ──────────────────────────────────────────────────

/// **The rule this crate has to satisfy and had no test for.**
///
/// Public signals leave through `field_to_le_hex`, and the chain rejects any
/// that do not round-trip. Arkworks' `to_bytes_le` already returns 32 bytes and
/// the elements are reduced by construction, so this passes today — the point
/// is that nothing was stopping a future edit from breaking it silently.
#[test]
fn every_signal_this_crate_emits_is_canonical() {
    let cases = [
        ("zero", Bn254Fr::from(0u64)),
        ("one", Bn254Fr::from(1u64)),
        ("small", Bn254Fr::from(42u64)),
        ("u64 max", Bn254Fr::from(u64::MAX)),
        ("negative one", -Bn254Fr::from(1u64)),
    ];
    for (name, f) in cases {
        let bytes = hex_to_le_bytes(&field_to_le_hex(&f));
        assert!(
            chain_accepts_public_input(&bytes),
            "the chain would reject the encoding of {name}"
        );
    }
}

/// The negative control. Without it the test above could pass against a rule
/// that accepts everything, which is no rule at all.
#[test]
fn a_non_canonical_encoding_is_rejected() {
    // p + 1: the same field element as 1, written the long way round.
    let mut bytes = Bn254Fr::MODULUS.to_bytes_le();
    bytes.resize(32, 0);
    let mut carry = 1u16;
    for byte in bytes.iter_mut() {
        let sum = u16::from(*byte) + carry;
        *byte = (sum & 0xff) as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
    let non_canonical: [u8; 32] = bytes[..32].try_into().unwrap();

    assert_eq!(
        Bn254Fr::from_le_bytes_mod_order(&non_canonical),
        Bn254Fr::from(1u64),
        "p+1 must reduce to 1, or this is testing the wrong thing"
    );
    assert!(
        !chain_accepts_public_input(&non_canonical),
        "the chain's rule accepted a non-canonical encoding"
    );
    // And the canonical spelling of that same element is fine.
    assert!(chain_accepts_public_input(&hex_to_le_bytes(
        &field_to_le_hex(&Bn254Fr::from(1u64))
    )));
}

/// The signals of a real witness, not just hand-made values.
#[test]
fn the_signals_of_a_real_proof_are_all_canonical() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let wit = require!(artifact("fixtures/unshield.witness.json"));

    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();
    let (witness, _) = load_witness(&wit);
    let _ = pk;

    let signals = public_inputs(&matrices, &witness).expect("witness fits the circuit");
    assert!(!signals.is_empty());
    assert!(
        signals.len() <= MAX_PUBLIC_INPUTS,
        "{} signals exceeds the chain's limit of {MAX_PUBLIC_INPUTS}",
        signals.len()
    );
    for (i, f) in signals.iter().enumerate() {
        assert!(
            chain_accepts_public_input(&hex_to_le_bytes(&field_to_le_hex(f))),
            "signal {i} would be rejected as non-canonical"
        );
    }
}

// ─── Proof and key sizes ─────────────────────────────────────────────────────

/// A proof must be 128 bytes, and comfortably inside the chain's ceiling.
#[test]
fn a_proof_is_128_bytes_and_within_the_chains_bound() {
    let zkey = require!(artifact("keys/unshield_pk.zkey"));
    let wit = require!(artifact("fixtures/unshield.witness.json"));

    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();
    let (witness, _) = load_witness(&wit);
    let proof = prove_circom(&pk, &matrices, &witness).expect("prove");

    assert_eq!(proof.len(), 128);
    assert!(proof.len() <= MAX_PROOF_BYTES);
    assert!(
        verify_proof(
            &pk.vk,
            public_inputs(&matrices, &witness).expect("witness fits the circuit"),
            &proof
        )
        .expect("verify"),
        "the proof under test does not verify, so its size proves nothing"
    );
}

/// The packed verifying key must match the size rule the chain's deserializer
/// implies, and stay under its bound.
///
/// `232 + IC × 32`: 32 for `alpha_g1`, 64 each for three G2 points, an 8-byte
/// length prefix, then one compressed G1 per IC element.
#[test]
fn a_packed_verifying_key_has_the_size_the_chain_expects() {
    for (name, arity) in ARITIES {
        let Some(vk_json) = artifact(&format!("build/verification_key_{name}.json")) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: no verifying key");
            continue;
        };
        let bytes = pack_snarkjs_vk(&std::fs::read_to_string(vk_json).unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        let ic_len = arity + 1;
        assert_eq!(
            bytes.len(),
            232 + ic_len * 32,
            "{name}: packed to {} bytes, expected {}",
            bytes.len(),
            232 + ic_len * 32
        );
        assert!(
            bytes.len() <= MAX_VK_BYTES,
            "{name}: exceeds the chain's key bound"
        );

        // And it must deserialize the way the runtime deserializes it.
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..])
            .unwrap_or_else(|e| panic!("{name}: the chain could not deserialize this key: {e}"));
        assert_eq!(
            vk.gamma_abc_g1.len(),
            ic_len,
            "{name}: IC length changed in the round trip"
        );
    }
}

// ─── Arity ───────────────────────────────────────────────────────────────────

/// Three independent sources must agree on how many public signals a circuit
/// has: the published manifest, the verifying key, and a table written by hand.
///
/// A mismatch is not a cosmetic inconsistency — a proof made against the wrong
/// arity is well-formed and unverifiable, with nothing in the output to say so.
#[test]
fn the_manifest_the_key_and_the_table_agree_on_arity() {
    let manifest = require!(artifact("manifest.json"), "manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();

    for (name, arity) in ARITIES {
        let Some(vk_json) = artifact(&format!("build/verification_key_{name}.json")) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: no verifying key");
            continue;
        };
        let vk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(vk_json).unwrap()).unwrap();

        assert_eq!(
            vk["nPublic"].as_u64().unwrap() as usize,
            *arity,
            "{name}: the verifying key disagrees with the table"
        );
        assert_eq!(
            vk["IC"].as_array().unwrap().len(),
            arity + 1,
            "{name}: IC length is not arity plus one"
        );

        // The manifest does not record arity directly, so the vk_hash is the
        // link: it identifies the key these numbers were read from.
        assert!(
            manifest["circuits"][name].is_object(),
            "{name} is missing from the manifest"
        );
    }
}

/// The proving key must state the same arity as the verifying key. These come
/// from the same trusted setup, and a disagreement means the artifacts were
/// built from different ceremonies — the failure the `.ark` desync produced.
#[test]
fn the_proving_key_agrees_with_the_table() {
    for (name, arity) in ARITIES {
        let Some(zkey) = artifact(&format!("keys/{name}_pk.zkey")) else {
            common::assert_artifacts();
            eprintln!("skipping {name}: no proving key");
            continue;
        };
        let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(zkey).unwrap())).unwrap();

        assert_eq!(
            matrices.num_instance_variables - 1,
            *arity,
            "{name}: the proving key's instance count disagrees with the table"
        );
        assert_eq!(
            pk.vk.gamma_abc_g1.len(),
            arity + 1,
            "{name}: the embedded verifying key disagrees with the table"
        );
    }
}

/// The verifying key this crate packs must be the one the chain registered.
///
/// `vk_hash` is `blake2_256` of exactly these bytes, so this catches a packing
/// change that would silently mint a key the chain does not recognise.
#[test]
fn the_packed_key_matches_the_manifests_hash() {
    let manifest = require!(artifact("manifest.json"), "manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();

    for (name, _) in ARITIES {
        let Some(vk_json) = artifact(&format!("build/verification_key_{name}.json")) else {
            continue;
        };
        let Some(expected) = manifest["circuits"][name]["versions"]["1"]["vk_hash"].as_str() else {
            common::assert_artifacts();
            eprintln!("skipping {name}: no vk_hash in the manifest");
            continue;
        };

        let bytes = pack_snarkjs_vk(&std::fs::read_to_string(vk_json).unwrap()).unwrap();
        let got = format!("0x{}", hex::encode(blake2_256(&bytes)));
        assert_eq!(
            got, expected,
            "{name}: the packed key does not hash to the registered vk_hash"
        );
    }
}

/// blake2b-512 truncated to 256 bits — what Substrate's `blake2_256` computes.
fn blake2_256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}
