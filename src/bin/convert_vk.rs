//! Convert snarkjs Groth16 VK JSON to arkworks compressed binary.
//!
//! Usage:
//!   convert_vk <input.json> [output.bin]
//!
//! If output is omitted, replaces .json with .bin.
//! Outputs the byte count to stderr.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use serde_json::Value;
use std::{env, fs, process};

fn parse_fq(s: &str) -> Fq {
    let n =
        BigUint::parse_bytes(s.as_bytes(), 10).unwrap_or_else(|| panic!("invalid Fq element: {s}"));
    Fq::from_le_bytes_mod_order(&n.to_bytes_le())
}

/// Parse a G1 affine point from snarkjs projective form [x, y, z].
/// For standard VK points z == "1" so affine == projective coordinates.
fn parse_g1(v: &Value) -> G1Affine {
    let x = parse_fq(v[0].as_str().expect("G1 x must be string"));
    let y = parse_fq(v[1].as_str().expect("G1 y must be string"));
    G1Affine::new(x, y)
}

/// Parse an Fq2 element from snarkjs array [c0, c1].
fn parse_fq2(v: &Value) -> Fq2 {
    let c0 = parse_fq(v[0].as_str().expect("Fq2 c0 must be string"));
    let c1 = parse_fq(v[1].as_str().expect("Fq2 c1 must be string"));
    Fq2::new(c0, c1)
}

/// Parse a G2 affine point from snarkjs projective form [[x.c0,x.c1],[y.c0,y.c1],[z.c0,z.c1]].
/// For standard VK points z == [1,0] so affine == projective coordinates.
fn parse_g2(v: &Value) -> G2Affine {
    let x = parse_fq2(&v[0]);
    let y = parse_fq2(&v[1]);
    G2Affine::new(x, y)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: convert_vk <input_vk.json> [output_vk.bin]");
        process::exit(1);
    }

    let in_path = &args[1];
    let out_path = if args.len() >= 3 {
        args[2].clone()
    } else if let Some(stripped) = in_path.strip_suffix(".json") {
        format!("{stripped}.bin")
    } else {
        format!("{in_path}.bin")
    };

    let json_str =
        fs::read_to_string(in_path).unwrap_or_else(|e| panic!("cannot read {in_path}: {e}"));

    let json: Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("invalid JSON in {in_path}: {e}"));

    let alpha_g1 = parse_g1(&json["vk_alpha_1"]);
    let beta_g2 = parse_g2(&json["vk_beta_2"]);
    let gamma_g2 = parse_g2(&json["vk_gamma_2"]);
    let delta_g2 = parse_g2(&json["vk_delta_2"]);

    let ic_arr = json["IC"]
        .as_array()
        .unwrap_or_else(|| panic!("missing IC field in {in_path}"));
    let gamma_abc_g1: Vec<G1Affine> = ic_arr.iter().map(parse_g1).collect();

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };

    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .unwrap_or_else(|e| panic!("serialization failed: {e}"));

    fs::write(&out_path, &bytes).unwrap_or_else(|e| panic!("cannot write {out_path}: {e}"));

    eprintln!(
        "Converted {} → {} ({} bytes JSON → {} bytes binary)",
        in_path,
        out_path,
        json_str.len(),
        bytes.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::BigInteger;
    use ark_groth16::VerifyingKey;
    use ark_serialize::CanonicalSerialize;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn fq_to_decimal(f: Fq) -> String {
        let bytes_le = f.into_bigint().to_bytes_le();
        BigUint::from_bytes_le(&bytes_le).to_str_radix(10)
    }

    fn g1_gen_json() -> Value {
        let g: G1Affine = G1Projective::generator().into_affine();
        serde_json::json!([fq_to_decimal(g.x), fq_to_decimal(g.y), "1"])
    }

    fn g2_gen_json() -> Value {
        let g: G2Affine = G2Projective::generator().into_affine();
        serde_json::json!([
            [fq_to_decimal(g.x.c0), fq_to_decimal(g.x.c1)],
            [fq_to_decimal(g.y.c0), fq_to_decimal(g.y.c1)],
            ["1", "0"]
        ])
    }

    /// Build a minimal but structurally valid snarkjs VK JSON with `num_ic` IC points.
    fn build_vk_json(num_ic: usize) -> Value {
        let ic: Vec<Value> = (0..num_ic).map(|_| g1_gen_json()).collect();
        serde_json::json!({
            "vk_alpha_1": g1_gen_json(),
            "vk_beta_2":  g2_gen_json(),
            "vk_gamma_2": g2_gen_json(),
            "vk_delta_2": g2_gen_json(),
            "IC": ic
        })
    }

    fn vk_from_json(json: &Value) -> VerifyingKey<Bn254> {
        let ic_arr = json["IC"].as_array().unwrap();
        VerifyingKey::<Bn254> {
            alpha_g1: parse_g1(&json["vk_alpha_1"]),
            beta_g2: parse_g2(&json["vk_beta_2"]),
            gamma_g2: parse_g2(&json["vk_gamma_2"]),
            delta_g2: parse_g2(&json["vk_delta_2"]),
            gamma_abc_g1: ic_arr.iter().map(parse_g1).collect(),
        }
    }

    // ── parse_fq ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_fq_zero() {
        assert_eq!(parse_fq("0"), Fq::from(0u64));
    }

    #[test]
    fn test_parse_fq_one() {
        assert_eq!(parse_fq("1"), Fq::from(1u64));
    }

    #[test]
    fn test_parse_fq_large_value() {
        // 2^64 — larger than u64, must survive mod-order reduction
        let big = "18446744073709551616";
        let result = std::panic::catch_unwind(|| parse_fq(big));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_fq_invalid_panics() {
        let result = std::panic::catch_unwind(|| parse_fq("not-a-number"));
        assert!(result.is_err());
    }

    // ── parse_g1 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_g1_roundtrip_generator() {
        let original: G1Affine = G1Projective::generator().into_affine();
        let json = g1_gen_json();
        let parsed = parse_g1(&json);
        assert_eq!(parsed, original);
    }

    // ── parse_g2 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_g2_roundtrip_generator() {
        let original: G2Affine = G2Projective::generator().into_affine();
        let json = g2_gen_json();
        let parsed = parse_g2(&json);
        assert_eq!(parsed, original);
    }

    // ── serialized VK size ────────────────────────────────────────────────────
    //
    // Compressed sizes on BN254:
    //   G1 affine  = 32 bytes
    //   G2 affine  = 64 bytes
    //   Vec<G1> header (u64 len) = 8 bytes
    //
    //   Total = 32 + 64*3 + 8 + n*32  =  232 + n*32

    #[test]
    fn test_vk_serialized_size_one_ic() {
        let vk = vk_from_json(&build_vk_json(1));
        let mut bytes = Vec::new();
        vk.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 264); // 232 + 1*32
    }

    #[test]
    fn test_vk_serialized_size_six_ic() {
        // 6 IC elements = 5 public signals + 1 (matches the unshield circuit)
        let vk = vk_from_json(&build_vk_json(6));
        let mut bytes = Vec::new();
        vk.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 424); // 232 + 6*32
    }

    // ── file round-trip ───────────────────────────────────────────────────────

    #[test]
    fn test_file_roundtrip_writes_correct_binary() {
        let json = build_vk_json(6);
        let json_str = json.to_string();

        let in_path = "/tmp/test_convert_vk_input.json";
        let out_path = "/tmp/test_convert_vk_output.bin";
        std::fs::write(in_path, &json_str).unwrap();

        // Run the same conversion logic as main()
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        let vk = vk_from_json(&parsed);
        let mut bytes = Vec::new();
        vk.serialize_compressed(&mut bytes).unwrap();
        std::fs::write(out_path, &bytes).unwrap();

        // Read back and verify
        let read_back = std::fs::read(out_path).unwrap();
        assert_eq!(read_back, bytes);
        assert_eq!(read_back.len(), 424);

        let _ = std::fs::remove_file(in_path);
        let _ = std::fs::remove_file(out_path);
    }

    // ── output path derivation ────────────────────────────────────────────────

    #[test]
    fn test_output_path_strips_json_suffix() {
        // Replicate the out_path logic from main()
        let in_path = "artifacts/verification_key_unshield.json".to_string();
        let out_path = if let Some(stripped) = in_path.strip_suffix(".json") {
            format!("{stripped}.bin")
        } else {
            format!("{in_path}.bin")
        };
        assert_eq!(out_path, "artifacts/verification_key_unshield.bin");
    }

    #[test]
    fn test_output_path_no_json_suffix_appends_bin() {
        let in_path = "mykey".to_string();
        let out_path = if let Some(stripped) = in_path.strip_suffix(".json") {
            format!("{stripped}.bin")
        } else {
            format!("{in_path}.bin")
        };
        assert_eq!(out_path, "mykey.bin");
    }
}
