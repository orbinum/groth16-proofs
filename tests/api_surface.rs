//! The public API, named by the paths consumers actually use.
//!
//! The crate's modules are grouped into layers — `core`, `format`, `groth16` —
//! but that grouping is an implementation detail: everything is re-exported
//! from the root, so `groth16_proofs::prove_circom` is the path rather than
//! `groth16_proofs::groth16::prove::prove_circom`.
//!
//! Nothing enforced that. Moving a module between layers and forgetting its
//! re-export compiles fine, passes every other test in this suite, and breaks
//! every consumer — the failure only appears in someone else's build. This file
//! is the check: if an item stops being reachable by its documented path, it
//! fails here instead.
//!
//! Adding an item to the list is how a new public API gets acknowledged.
//! Removing one should mean a major version.

use groth16_proofs::{
    compress_snarkjs_proof, field_to_le_hex, from_decimal_str, pack_snarkjs_vk, parse_snarkjs_vk,
    parse_witness_json, prove_circom, public_inputs, read_ark_v2, read_zkey, verify_proof,
    witness_from_le_bytes, write_ark_v2, ConstraintMatrices, ProofError, WitnessFile, ARK_V2_MAGIC,
    ARK_V2_VERSION, FIELD_BYTES, MAX_ARTIFACT_BYTES,
};

/// The constants, which are part of the contract rather than incidental.
// The largest published circuit is transfer at 9.6 MB. A limit that does not
// clear it with room to spare would reject a legitimate artifact.
//
// At module scope on purpose: this is a compile-time assertion, and inside a
// `#[test]` body it looked like one the test runner evaluates. It fires whether
// or not any test runs.
const _: () = assert!(MAX_ARTIFACT_BYTES >= 16 * 1024 * 1024);

#[test]
fn the_exported_constants_hold_their_documented_values() {
    assert_eq!(
        FIELD_BYTES, 32,
        "a BN254 element is 32 bytes in every encoding"
    );
    assert_eq!(ARK_V2_VERSION, 2);
    assert_eq!(ARK_V2_MAGIC, b"ORBARKV2");
}

/// Every exported function, referenced so the import above cannot be reduced to
/// an unused-import warning that someone later "cleans up".
#[test]
fn every_exported_item_is_reachable() {
    let _: fn(&str) -> _ = compress_snarkjs_proof;
    let _: fn(&str) -> _ = pack_snarkjs_vk;
    let _: fn(&str) -> _ = parse_snarkjs_vk;
    let _: fn(&str) -> _ = parse_witness_json;
    let _: fn(&[u8]) -> _ = witness_from_le_bytes;
    let _: fn(&[u8]) -> _ = read_ark_v2;
    let _ = field_to_le_hex as fn(&ark_bn254::Fr) -> String;
    let _ = from_decimal_str::<ark_bn254::Fr> as fn(&str) -> _;
    let _ = prove_circom;
    let _ = public_inputs;
    let _ = verify_proof;
    let _ = write_ark_v2;
    let _ = read_zkey::<std::io::Cursor<Vec<u8>>>;

    // Types, named rather than called.
    fn takes_types(_: Option<ProofError>, _: Option<WitnessFile>) {}
    takes_types(None, None);
    let _: Option<ConstraintMatrices<ark_bn254::Fr>> = None;
}
