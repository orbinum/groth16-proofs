//! snarkjs interop: its JSON on one side, arkworks' binary encoding on the other.
//!
//! Two things arrive from snarkjs — proofs and verifying keys — and both are
//! the same shape underneath: BN254 curve points written as decimal strings.
//! They used to be parsed twice, by `codec.rs` returning `Result` and by
//! `pack_verifying_key.rs` panicking, each interpreting G2's nested
//! `[[c0,c1],[c0,c1]]` ordering on its own.
//!
//! That ordering is the part worth centralising. An Fq2 written in the wrong
//! coordinate order produces a point that is still on the curve, still
//! serializes to the right number of bytes, and never verifies — the same
//! failure signature as the QAP-reduction bug, and just as invisible. With one
//! implementation, a fix reaches both callers; with two, it reaches whichever
//! one someone remembered.
//!
//! # Projective input, affine output
//!
//! snarkjs writes points projectively: G1 as `[x, y, z]`, G2 as
//! `[[x.c0,x.c1], [y.c0,y.c1], [z.c0,z.c1]]`. For proofs and verifying keys
//! `z` is always `1` (`[1,0]` for G2), so the leading two entries are already
//! affine coordinates and the third is ignored. A `z` that is not 1 would need
//! a division that these parsers do not perform — it does not occur in snarkjs
//! output, and a silent wrong answer is worse than not handling it, so the
//! parsers below read exactly two coordinates and leave it at that.

//! # The three verbs
//!
//! Three names for two operations, which is worth stating because they do not
//! pair up the way they look:
//!
//! - `parse_snarkjs_vk` — JSON to an arkworks `VerifyingKey`. The only one that
//!   yields a Rust type.
//! - `pack_snarkjs_vk` — JSON to the bytes the chain stores. Parses, then
//!   re-serializes compressed.
//! - `compress_snarkjs_proof` — the same shape for a proof: JSON in, the chain's
//!   128 bytes out.
//!
//! So `parse_` gives you a type to work with, and `pack_`/`compress_` give you
//! the chain's bytes. `pack_` and `parse_` are not inverses despite the reading —
//! both take `&str` and go the same direction. The inverse of `pack_snarkjs_vk`
//! would be arkworks-bytes-to-JSON, which nothing needs and which does not exist.
//!
//! The names are consensus-facing (`pack_snarkjs_vk`'s output is the `vk_hash`
//! preimage), so they are kept as they are rather than made symmetric.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_groth16::{Proof as ArkProof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use serde_json::Value;

use crate::core::error::ProofError;
use crate::core::field::from_decimal_str;

// ─── Point primitives ────────────────────────────────────────────────────────
//
// Each takes a `ctx` naming the field it came from, so a malformed coordinate
// says "vk_beta_2.x.c1" rather than "invalid decimal string".

/// A base-field element from its decimal string.
pub(crate) fn fq_from_decimal(s: &str, ctx: &str) -> Result<Fq, ProofError> {
    from_decimal_str::<Fq>(s).map_err(|e| ProofError::SnarkjsParse(format!("{ctx}: {e}")))
}

/// A G1 point from its two affine coordinates.
///
/// Built with `new_unchecked` and validated explicitly. `G1Affine::new` asserts
/// — in release as well as debug — so it aborts the process on input that is
/// merely malformed. This JSON arrives from a file, so a bad point has to be an
/// error a caller can handle, not a panic.
pub(crate) fn g1_from_decimal(xy: [&str; 2], ctx: &str) -> Result<G1Affine, ProofError> {
    let p = G1Affine::new_unchecked(
        fq_from_decimal(xy[0], &format!("{ctx}.x"))?,
        fq_from_decimal(xy[1], &format!("{ctx}.y"))?,
    );
    validate(p, ctx)
}

/// A quadratic-extension element from `[c0, c1]`.
///
/// The order is the one thing here that cannot be checked locally: `c0` and
/// `c1` are both valid field elements either way round, so a swap is only
/// visible as a proof that fails to verify.
pub(crate) fn fq2_from_decimal(c: [&str; 2], ctx: &str) -> Result<Fq2, ProofError> {
    Ok(Fq2::new(
        fq_from_decimal(c[0], &format!("{ctx}.c0"))?,
        fq_from_decimal(c[1], &format!("{ctx}.c1"))?,
    ))
}

/// A G2 point from its two affine Fq2 coordinates.
///
/// Unchecked construction plus explicit validation, for the same reason as
/// [`g1_from_decimal`].
pub(crate) fn g2_from_decimal(xy: [[&str; 2]; 2], ctx: &str) -> Result<G2Affine, ProofError> {
    let p = G2Affine::new_unchecked(
        fq2_from_decimal(xy[0], &format!("{ctx}.x"))?,
        fq2_from_decimal(xy[1], &format!("{ctx}.y"))?,
    );
    validate(p, ctx)
}

/// Both curve checks arkworks' `new` would assert on, as a recoverable error.
///
/// The subgroup check is the one that carries weight: a point on the curve but
/// in the wrong subgroup passes a naive on-curve test and breaks the soundness
/// of the pairing. Verifying keys arrive from a build pipeline rather than an
/// attacker, but they arrive as a *file*, and a file can be wrong.
fn validate<P: SWCurveConfig>(p: Affine<P>, ctx: &str) -> Result<Affine<P>, ProofError> {
    if !p.is_on_curve() {
        return Err(ProofError::SnarkjsParse(format!(
            "{ctx}: point is not on the curve"
        )));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ProofError::SnarkjsParse(format!(
            "{ctx}: point is not in the prime-order subgroup"
        )));
    }
    Ok(p)
}

// ─── JSON access ─────────────────────────────────────────────────────────────

/// A decimal string at `value[i]`, or an error naming what was expected.
fn str_at(value: &Value, i: usize, ctx: &str) -> Result<String, ProofError> {
    value[i]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ProofError::SnarkjsParse(format!("{ctx}[{i}] is not a string")))
}

/// A G1 point from snarkjs projective form `[x, y, z]`.
fn g1_from_json(value: &Value, ctx: &str) -> Result<G1Affine, ProofError> {
    let x = str_at(value, 0, ctx)?;
    let y = str_at(value, 1, ctx)?;
    g1_from_decimal([&x, &y], ctx)
}

/// A G2 point from snarkjs projective form `[[x.c0,x.c1], [y.c0,y.c1], _]`.
fn g2_from_json(value: &Value, ctx: &str) -> Result<G2Affine, ProofError> {
    let xc = &value[0];
    let yc = &value[1];
    let x0 = str_at(xc, 0, &format!("{ctx}.x"))?;
    let x1 = str_at(xc, 1, &format!("{ctx}.x"))?;
    let y0 = str_at(yc, 0, &format!("{ctx}.y"))?;
    let y1 = str_at(yc, 1, &format!("{ctx}.y"))?;
    g2_from_decimal([[&x0, &x1], [&y0, &y1]], ctx)
}

// ─── Proofs ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

/// Check the array shapes before anything indexes into them.
///
/// `parse_proof` reads `pi_a[0]`, `pi_b[1][0]` and so on directly, so it would
/// panic on a short array. This runs first and turns every such case into an
/// error — the ordering is the safety property, and `compress_snarkjs_proof` is
/// the only caller of either function precisely so it cannot be got wrong.
///
/// The bounds are `>=`, not `==`: snarkjs appends a projective `z` that is always
/// 1 and that these parsers ignore, so a three-element G1 is the normal case.
fn validate_structure(proof: &SnarkjsProof) -> Result<(), ProofError> {
    if proof.pi_a.len() < 2 {
        return Err(ProofError::SnarkjsParse(
            "pi_a must contain at least 2 elements".into(),
        ));
    }
    if proof.pi_b.len() < 2 || proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(ProofError::SnarkjsParse("pi_b must be a 2x2 matrix".into()));
    }
    if proof.pi_c.len() < 2 {
        return Err(ProofError::SnarkjsParse(
            "pi_c must contain at least 2 elements".into(),
        ));
    }
    Ok(())
}

/// Build an arkworks proof from validated JSON.
///
/// **Precondition:** `validate_structure` has returned `Ok` for this proof. The
/// indexing below is unchecked, and the shapes are what make it safe.
fn parse_proof(proof: &SnarkjsProof) -> Result<ArkProof<Bn254>, ProofError> {
    Ok(ArkProof::<Bn254> {
        a: g1_from_decimal([&proof.pi_a[0], &proof.pi_a[1]], "pi_a")?,
        b: g2_from_decimal(
            [
                [&proof.pi_b[0][0], &proof.pi_b[0][1]],
                [&proof.pi_b[1][0], &proof.pi_b[1][1]],
            ],
            "pi_b",
        )?,
        c: g1_from_decimal([&proof.pi_c[0], &proof.pi_c[1]], "pi_c")?,
    })
}

/// A snarkjs proof JSON as the 128-byte arkworks compressed form the chain takes.
pub fn compress_snarkjs_proof(proof_json: &str) -> Result<Vec<u8>, ProofError> {
    let parsed: SnarkjsProof =
        serde_json::from_str(proof_json).map_err(|e| ProofError::SnarkjsParse(e.to_string()))?;
    validate_structure(&parsed)?;
    let proof = parse_proof(&parsed)?;
    let mut compressed = Vec::new();
    proof
        .serialize_compressed(&mut compressed)
        .map_err(|e| ProofError::ProofSerialization(e.to_string()))?;
    Ok(compressed)
}

// ─── Verifying keys ──────────────────────────────────────────────────────────

/// A snarkjs `verification_key.json` as an arkworks verifying key.
pub fn parse_snarkjs_vk(vk_json: &str) -> Result<VerifyingKey<Bn254>, ProofError> {
    let json: Value =
        serde_json::from_str(vk_json).map_err(|e| ProofError::SnarkjsParse(e.to_string()))?;

    let ic = json["IC"]
        .as_array()
        .ok_or_else(|| ProofError::SnarkjsParse("missing or non-array IC field".into()))?;
    if ic.is_empty() {
        return Err(ProofError::SnarkjsParse(
            "IC is empty — a verifying key has one element per public input plus one".into(),
        ));
    }

    Ok(VerifyingKey::<Bn254> {
        alpha_g1: g1_from_json(&json["vk_alpha_1"], "vk_alpha_1")?,
        beta_g2: g2_from_json(&json["vk_beta_2"], "vk_beta_2")?,
        gamma_g2: g2_from_json(&json["vk_gamma_2"], "vk_gamma_2")?,
        delta_g2: g2_from_json(&json["vk_delta_2"], "vk_delta_2")?,
        gamma_abc_g1: ic
            .iter()
            .enumerate()
            .map(|(i, p)| g1_from_json(p, &format!("IC[{i}]")))
            .collect::<Result<_, _>>()?,
    })
}

/// A snarkjs `verification_key.json` as the compressed bytes the chain registers.
///
/// The output is `232 + IC.len() * 32` bytes: 32 for `alpha_g1`, three G2
/// points at 64 each, an 8-byte little-endian length prefix, then one
/// compressed G1 per IC element. For a 7-signal circuit that is 488 bytes.
///
/// `blake2_256` of this output is the `vk_hash` the chain identifies the key
/// by, so the encoding is consensus-relevant: two byte-different encodings of
/// the same key are two different keys as far as the chain is concerned.
pub fn pack_snarkjs_vk(vk_json: &str) -> Result<Vec<u8>, ProofError> {
    let vk = parse_snarkjs_vk(vk_json)?;
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .map_err(|e| ProofError::ProofSerialization(e.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Projective, G2Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_serialize::CanonicalDeserialize;
    use num_bigint::BigUint;

    fn fq_to_decimal_string(value: Fq) -> String {
        value
            .into_bigint()
            .to_bytes_le()
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |acc, &byte| {
                (acc << 8) + BigUint::from(byte)
            })
            .to_str_radix(10)
    }

    fn build_valid_snarkjs_proof_json() -> String {
        let a = G1Projective::generator().into_affine();
        let b = G2Projective::generator().into_affine();
        let c = G1Projective::generator().into_affine();
        serde_json::json!({
            "pi_a": [fq_to_decimal_string(a.x), fq_to_decimal_string(a.y)],
            "pi_b": [
                [fq_to_decimal_string(b.x.c0), fq_to_decimal_string(b.x.c1)],
                [fq_to_decimal_string(b.y.c0), fq_to_decimal_string(b.y.c1)]
            ],
            "pi_c": [fq_to_decimal_string(c.x), fq_to_decimal_string(c.y)]
        })
        .to_string()
    }

    /// A verifying key in snarkjs shape, with `ic_len` IC entries, written
    /// projectively the way snarkjs does — trailing `z` included, so the
    /// parsers are exercised against the real input shape rather than a
    /// convenient one.
    fn build_valid_snarkjs_vk_json(ic_len: usize) -> String {
        let g1 = G1Projective::generator().into_affine();
        let g2 = G2Projective::generator().into_affine();
        let g1_json =
            serde_json::json!([fq_to_decimal_string(g1.x), fq_to_decimal_string(g1.y), "1"]);
        let g2_json = serde_json::json!([
            [fq_to_decimal_string(g2.x.c0), fq_to_decimal_string(g2.x.c1)],
            [fq_to_decimal_string(g2.y.c0), fq_to_decimal_string(g2.y.c1)],
            ["1", "0"]
        ]);
        serde_json::json!({
            "protocol": "groth16",
            "curve": "bn128",
            "nPublic": ic_len - 1,
            "vk_alpha_1": g1_json,
            "vk_beta_2": g2_json,
            "vk_gamma_2": g2_json,
            "vk_delta_2": g2_json,
            "IC": vec![g1_json.clone(); ic_len],
        })
        .to_string()
    }

    // ─── Proofs ──────────────────────────────────────────────────────────────

    #[test]
    fn compressing_a_proof_produces_128_bytes() {
        let bytes = compress_snarkjs_proof(&build_valid_snarkjs_proof_json()).unwrap();
        assert_eq!(bytes.len(), 128);
    }

    #[test]
    fn compressing_matches_arkworks_own_serialization() {
        let proof_json = build_valid_snarkjs_proof_json();
        let bytes = compress_snarkjs_proof(&proof_json).unwrap();

        let parsed: SnarkjsProof = serde_json::from_str(&proof_json).unwrap();
        let proof = parse_proof(&parsed).unwrap();
        let mut expected = Vec::new();
        proof.serialize_compressed(&mut expected).unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn malformed_proof_json_is_refused() {
        assert!(compress_snarkjs_proof("not valid json {{{{").is_err());
    }

    #[test]
    fn a_short_pi_a_is_refused() {
        let proof_json = serde_json::json!({
            "pi_a": ["1"],
            "pi_b": [["1", "2"], ["3", "4"]],
            "pi_c": ["1", "2"]
        })
        .to_string();
        let err = compress_snarkjs_proof(&proof_json).unwrap_err();
        assert!(err
            .to_string()
            .contains("pi_a must contain at least 2 elements"));
    }

    #[test]
    fn a_pi_b_with_no_rows_is_refused() {
        let proof = SnarkjsProof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![],
            pi_c: vec!["1".into(), "2".into()],
        };
        let err = validate_structure(&proof).unwrap_err();
        assert!(err.to_string().contains("pi_b must be a 2x2 matrix"));
    }

    #[test]
    fn a_pi_b_with_short_rows_is_refused() {
        let proof = SnarkjsProof {
            pi_a: vec!["1".into(), "2".into()],
            pi_b: vec![vec!["1".into()], vec!["3".into(), "4".into()]],
            pi_c: vec!["1".into(), "2".into()],
        };
        let err = validate_structure(&proof).unwrap_err();
        assert!(err.to_string().contains("pi_b must be a 2x2 matrix"));
    }

    // ─── Point primitives ────────────────────────────────────────────────────

    /// The reason these live in one place. `Fq2::new(c0, c1)` and
    /// `Fq2::new(c1, c0)` are both valid field elements, so a swapped pair is
    /// caught by nothing except a proof that will not verify.
    #[test]
    fn fq2_reads_c0_first() {
        let e = fq2_from_decimal(["1", "2"], "test").unwrap();
        assert_eq!(e.c0, Fq::from(1u64));
        assert_eq!(e.c1, Fq::from(2u64));
    }

    /// Likewise for G2: x before y, each of them c0 before c1.
    ///
    /// Checked against the curve generator rather than made-up coordinates —
    /// `G2Affine::new` asserts the point is on the curve, so the only way to
    /// exercise the ordering is with a point that really is.
    #[test]
    fn g2_reads_x_before_y() {
        let g = G2Projective::generator().into_affine();
        let p = g2_from_decimal(
            [
                [&fq_to_decimal_string(g.x.c0), &fq_to_decimal_string(g.x.c1)],
                [&fq_to_decimal_string(g.y.c0), &fq_to_decimal_string(g.y.c1)],
            ],
            "test",
        )
        .unwrap();
        assert_eq!(p, g, "the generator did not survive a round trip");
        assert_eq!(p.x.c0, g.x.c0);
        assert_eq!(p.x.c1, g.x.c1);
        assert_eq!(p.y.c0, g.y.c0);
        assert_eq!(p.y.c1, g.y.c1);
    }

    /// The swap that centralising these parsers exists to prevent. Feeding the
    /// coordinates in the wrong order gives a point that is not on the curve,
    /// and that must be an error rather than an abort — arkworks' own
    /// `G2Affine::new` asserts here, in release builds too.
    #[test]
    fn swapping_g2_coordinates_is_refused_rather_than_aborting() {
        let g = G2Projective::generator().into_affine();
        let err = g2_from_decimal(
            [
                [&fq_to_decimal_string(g.x.c1), &fq_to_decimal_string(g.x.c0)],
                [&fq_to_decimal_string(g.y.c0), &fq_to_decimal_string(g.y.c1)],
            ],
            "pi_b",
        )
        .unwrap_err();
        assert!(err.to_string().contains("curve"), "got: {err}");
    }

    /// A point off the curve in a verifying key must be an error too. This is
    /// the case that used to take the whole process down.
    #[test]
    fn a_vk_with_a_point_off_the_curve_is_refused_rather_than_aborting() {
        let mut json: Value = serde_json::from_str(&build_valid_snarkjs_vk_json(8)).unwrap();
        // (1, 1) is not on y² = x³ + 3.
        json["vk_alpha_1"] = serde_json::json!(["1", "1", "1"]);
        let err = pack_snarkjs_vk(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("vk_alpha_1"), "got: {err}");
        assert!(err.to_string().contains("curve"), "got: {err}");
    }

    /// A malformed coordinate must say which one it was. "invalid decimal
    /// string" in a key with eleven points is not a usable message.
    #[test]
    fn a_bad_coordinate_names_itself() {
        let err = g2_from_decimal([["1", "nope"], ["3", "4"]], "vk_beta_2").unwrap_err();
        assert!(err.to_string().contains("vk_beta_2.x.c1"), "got: {err}");
    }

    #[test]
    fn an_invalid_decimal_is_refused() {
        let err = fq_from_decimal("not-a-number", "ctx").unwrap_err();
        assert!(err.to_string().contains("ctx"));
    }

    // ─── Verifying keys ──────────────────────────────────────────────────────

    /// The size rule the chain depends on: 232 bytes of fixed points plus 32
    /// per IC element. A 7-signal circuit has 8 IC entries and packs to 488.
    #[test]
    fn a_packed_vk_has_the_documented_size() {
        for ic_len in [5usize, 8] {
            let bytes = pack_snarkjs_vk(&build_valid_snarkjs_vk_json(ic_len)).unwrap();
            assert_eq!(
                bytes.len(),
                232 + ic_len * 32,
                "IC length {ic_len} packed to the wrong size"
            );
        }
        assert_eq!(
            pack_snarkjs_vk(&build_valid_snarkjs_vk_json(8))
                .unwrap()
                .len(),
            488,
            "the 7-signal circuits must pack to 488 bytes"
        );
    }

    /// Packing must round-trip through arkworks' own deserializer — that is
    /// what the chain runs on the bytes.
    #[test]
    fn a_packed_vk_deserializes_back_to_the_same_key() {
        let json = build_valid_snarkjs_vk_json(8);
        let parsed = parse_snarkjs_vk(&json).unwrap();
        let bytes = pack_snarkjs_vk(&json).unwrap();

        let back = VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(back.alpha_g1, parsed.alpha_g1);
        assert_eq!(back.beta_g2, parsed.beta_g2);
        assert_eq!(back.gamma_g2, parsed.gamma_g2);
        assert_eq!(back.delta_g2, parsed.delta_g2);
        assert_eq!(back.gamma_abc_g1, parsed.gamma_abc_g1);
    }

    /// Packing is deterministic. The `vk_hash` the chain registers is a hash of
    /// these bytes, so a nondeterministic encoding would be a consensus bug.
    #[test]
    fn packing_is_deterministic() {
        let json = build_valid_snarkjs_vk_json(8);
        assert_eq!(
            pack_snarkjs_vk(&json).unwrap(),
            pack_snarkjs_vk(&json).unwrap()
        );
    }

    #[test]
    fn a_vk_without_ic_is_refused() {
        let mut json: Value = serde_json::from_str(&build_valid_snarkjs_vk_json(8)).unwrap();
        json.as_object_mut().unwrap().remove("IC");
        let err = pack_snarkjs_vk(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("IC"), "got: {err}");
    }

    /// An empty IC would deserialize into a key that verifies nothing. The old
    /// binary accepted it silently.
    #[test]
    fn a_vk_with_an_empty_ic_is_refused() {
        let mut json: Value = serde_json::from_str(&build_valid_snarkjs_vk_json(8)).unwrap();
        json["IC"] = serde_json::json!([]);
        let err = pack_snarkjs_vk(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("IC is empty"), "got: {err}");
    }

    /// A missing point is an error, not a panic. This is the case the previous
    /// implementation handled with `.expect("G1 x must be string")`.
    #[test]
    fn a_vk_with_a_missing_point_is_refused_without_panicking() {
        let mut json: Value = serde_json::from_str(&build_valid_snarkjs_vk_json(8)).unwrap();
        json.as_object_mut().unwrap().remove("vk_alpha_1");
        let err = pack_snarkjs_vk(&json.to_string()).unwrap_err();
        assert!(err.to_string().contains("vk_alpha_1"), "got: {err}");
    }

    #[test]
    fn malformed_vk_json_is_refused() {
        assert!(pack_snarkjs_vk("{ not json").is_err());
    }
}
