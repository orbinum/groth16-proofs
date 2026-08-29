//! Field-element conversion, in the encodings that cross this crate's borders.
//!
//! Three formats meet here: snarkjs writes decimal strings, a `.wtns` file's
//! data section is little-endian 32-byte words, and the chain reads public
//! signals as little-endian 32-byte hex. None of them is arkworks' own
//! encoding, so every one of them is a conversion someone has to get right.

use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::core::error::ProofError;

/// The width of a BN254 field element in bytes, in every encoding here.
pub const FIELD_BYTES: usize = 32;

/// Parse a decimal string into any `PrimeField` element (snarkjs native wire format).
///
/// The string must be *canonical*: digits only, no leading zeros (except `"0"`
/// itself), and a value below the field modulus. Anything else is an error.
///
/// # Why the strictness
///
/// `BigUint::parse_bytes` is lenient in ways snarkjs never exercises — it accepts
/// a leading `+` and skips `_` separators — and `from_le_bytes_mod_order` reduces
/// an out-of-range value rather than rejecting it. Together those made this
/// function many-to-one, and it feeds `pack_snarkjs_vk`, whose `blake2_256` is the
/// `vk_hash` the chain registers a key by.
///
/// Measured on a real verifying key before this check existed: `x`, `x + p`,
/// `"000…x"` and `"2_049…"` all packed to identical bytes and therefore the same
/// `vk_hash`. That is not a forgery — `x` and `x + p` are the same field element,
/// and both keys verify the same proofs — but it means the JSON someone audits
/// and the JSON someone registers can differ textually and be indistinguishable
/// afterwards. The doc on `pack_snarkjs_vk` claims the encoding is
/// consensus-relevant; this is what makes that true in both directions.
///
/// Verified against every published artifact: 0 of 51,814 witness elements and 0
/// verifying-key coordinates are non-canonical, so nothing real is rejected.
pub fn from_decimal_str<F: PrimeField>(s: &str) -> Result<F, String> {
    if s.is_empty() {
        return Err("Failed to parse decimal string: empty".to_string());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "Failed to parse decimal string: {s} — digits only, no sign or separators"
        ));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(format!(
            "Failed to parse decimal string: {s} — leading zeros are not canonical"
        ));
    }

    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| format!("Failed to parse decimal string: {s}"))?;

    // `from_le_bytes_mod_order` would reduce silently, which is the whole problem.
    if n >= F::MODULUS.into() {
        return Err(format!(
            "Failed to parse decimal string: {s} — at or above the field modulus"
        ));
    }

    Ok(F::from_le_bytes_mod_order(&n.to_bytes_le()))
}

/// A witness from the little-endian bytes a `.wtns` file's data section holds.
///
/// This is the format the witness already exists in: `n × 32` little-endian
/// bytes, index 0 being the constant 1. The alternative the crate used before
/// 3.1.0 was to serialize those elements to decimal strings — hundreds of
/// kilobytes of JSON for a 16,928-element witness, parsed back one BigUint at a
/// time — so this is both the faster path and the one with less to go wrong.
///
/// Elements are reduced modulo the field. A `.wtns` produced by snarkjs never
/// contains an out-of-range value, so reduction is unreachable in practice, but
/// it means malformed input yields a wrong proof rather than an error. Callers
/// handling untrusted witness bytes should check canonicity themselves.
pub fn witness_from_le_bytes(bytes: &[u8]) -> Result<Vec<Bn254Fr>, ProofError> {
    if !bytes.len().is_multiple_of(FIELD_BYTES) {
        return Err(ProofError::WitnessLength(format!(
            "witness is {} bytes, not a multiple of {FIELD_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(FIELD_BYTES)
        .map(Bn254Fr::from_le_bytes_mod_order)
        .collect())
}

/// A field element as the 32-byte little-endian hex the chain expects.
///
/// The width is not cosmetic. The chain reads each public signal as a fixed
/// 32-byte little-endian word and rejects any encoding that does not reproduce
/// itself after being reduced and re-encoded, so a short or big-endian value is
/// not merely unusual — it is a different claim, or no claim at all.
///
/// Arkworks' `to_bytes_le` already returns 32 bytes for BN254, and the elements
/// reaching this function are reduced by construction, so the output is always
/// canonical. `tests/chain_rules.rs` pins that against the chain's own rule
/// rather than leaving it as an assumption.
pub fn field_to_le_hex(f: &Bn254Fr) -> String {
    let mut bytes = f.into_bigint().to_bytes_le();
    bytes.resize(FIELD_BYTES, 0);
    format!("0x{}", hex::encode(bytes))
}

/// The witness JSON that `make-fixture.ts` writes and two binaries read.
#[derive(serde::Deserialize)]
pub struct WitnessFile {
    /// The circuit's public-signal count. Optional in the format, but a caller
    /// that guesses it produces an unverifiable proof with nothing to explain
    /// why, so consumers should require it.
    pub num_public_signals: Option<usize>,
    /// The full witness as decimal strings, index 0 being the constant 1.
    pub witness: Vec<String>,
}

/// Parse a witness JSON file into field elements alongside its declared arity.
pub fn parse_witness_json(json: &str) -> Result<(Vec<Bn254Fr>, Option<usize>), ProofError> {
    let file: WitnessFile =
        serde_json::from_str(json).map_err(|e| ProofError::WitnessJsonParse(e.to_string()))?;
    let witness = file
        .witness
        .iter()
        .enumerate()
        .map(|(i, s)| {
            from_decimal_str::<Bn254Fr>(s)
                .map_err(|e| ProofError::WitnessJsonParse(format!("witness[{i}]: {e}")))
        })
        .collect::<Result<_, _>>()?;
    Ok((witness, file.num_public_signals))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_one() {
        assert_eq!(
            from_decimal_str::<Bn254Fr>("1").unwrap(),
            Bn254Fr::from(1u64)
        );
    }

    #[test]
    fn test_decimal_zero() {
        assert_eq!(
            from_decimal_str::<Bn254Fr>("0").unwrap(),
            Bn254Fr::from(0u64)
        );
    }

    #[test]
    fn test_decimal_large() {
        assert!(from_decimal_str::<Bn254Fr>("12345678901234567890").is_ok());
    }

    #[test]
    fn test_decimal_invalid() {
        let err = from_decimal_str::<Bn254Fr>("not_a_number").unwrap_err();
        assert!(err.contains("Failed to parse decimal string"));
    }

    #[test]
    fn test_decimal_empty() {
        let err = from_decimal_str::<Bn254Fr>("").unwrap_err();
        assert!(err.contains("Failed to parse decimal string"));
    }

    /// Non-canonical decimal is refused rather than normalised.
    ///
    /// This test previously asserted the opposite — that `"0001"` and `"1"` parse
    /// equal. They do denote the same field element, and accepting both was
    /// harmless in isolation. It stopped being harmless once this function fed
    /// `pack_snarkjs_vk`, whose output is hashed into the `vk_hash` the chain
    /// registers: several spellings of one key meant several JSON files with one
    /// hash.
    #[test]
    fn non_canonical_decimal_is_refused() {
        // Same value, four spellings snarkjs never emits.
        for s in ["0001", "+1", "1_0", " 1"] {
            let err = from_decimal_str::<Bn254Fr>(s).unwrap_err();
            assert!(
                err.contains("Failed to parse decimal string"),
                "{s} should be refused, got: {err}"
            );
        }

        // The canonical spelling still parses, and "0" is canonical for zero.
        assert_eq!(
            from_decimal_str::<Bn254Fr>("1").unwrap(),
            Bn254Fr::from(1u64)
        );
        assert_eq!(
            from_decimal_str::<Bn254Fr>("0").unwrap(),
            Bn254Fr::from(0u64)
        );
    }

    /// A value at or above the modulus is refused rather than reduced.
    ///
    /// `from_le_bytes_mod_order` would silently return `x mod p`, so `x` and
    /// `x + p` packed to identical bytes — measured on a real verifying key.
    #[test]
    fn a_value_at_or_above_the_modulus_is_refused() {
        let p = BigUint::from(Bn254Fr::MODULUS);

        for n in [p.clone(), &p + 1u32, &p * 2u32] {
            let err = from_decimal_str::<Bn254Fr>(&n.to_str_radix(10)).unwrap_err();
            assert!(err.contains("modulus"), "got: {err}");
        }

        // One below the modulus is the largest legal element.
        let max = &p - 1u32;
        assert!(from_decimal_str::<Bn254Fr>(&max.to_str_radix(10)).is_ok());
    }

    // ─── witness_from_le_bytes ───────────────────────────────────────────────

    /// The happy path, and the one that had no test at all while this logic
    /// lived inline in `wasm.rs`.
    #[test]
    fn a_witness_round_trips_through_little_endian_bytes() {
        let original: Vec<Bn254Fr> = (0..4u64).map(Bn254Fr::from).collect();
        let mut bytes = Vec::new();
        for f in &original {
            let mut le = f.into_bigint().to_bytes_le();
            le.resize(FIELD_BYTES, 0);
            bytes.extend_from_slice(&le);
        }
        assert_eq!(witness_from_le_bytes(&bytes).unwrap(), original);
    }

    /// A truncated buffer is the realistic corruption — a partial read, a
    /// wrong offset into a `.wtns` — and it must be named rather than silently
    /// dropping the tail.
    #[test]
    fn a_witness_that_is_not_a_whole_number_of_elements_is_refused() {
        let err = witness_from_le_bytes(&[0u8; 33]).unwrap_err();
        assert!(err.to_string().contains("33 bytes"), "got: {err}");
    }

    #[test]
    fn an_empty_witness_buffer_yields_no_elements() {
        assert!(witness_from_le_bytes(&[]).unwrap().is_empty());
    }

    // ─── field_to_le_hex ─────────────────────────────────────────────────────

    /// The chain reads public signals as 32-byte little-endian words, and a
    /// wallet comparing them against its own values needs the padding to be
    /// exact — a short encoding silently changes which value is being claimed.
    #[test]
    fn public_signals_are_32_byte_little_endian_hex() {
        let hex = field_to_le_hex(&Bn254Fr::from(42u64));
        assert_eq!(hex.len(), 66, "0x plus 64 hex characters");
        assert!(hex.starts_with("0x2a"), "42 little-endian starts with 0x2a");
        assert!(hex.ends_with("00"), "the high bytes are zero padding");
    }

    /// Zero must still occupy a full word rather than collapsing to "0x".
    #[test]
    fn zero_is_a_full_width_word() {
        assert_eq!(
            field_to_le_hex(&Bn254Fr::from(0u64)),
            format!("0x{}", "00".repeat(32))
        );
    }

    /// A value using the full width, to catch a `resize` that truncates instead
    /// of padding.
    #[test]
    fn a_large_field_element_keeps_all_its_bytes() {
        let hex = field_to_le_hex(&Bn254Fr::from(u64::MAX));
        assert_eq!(hex.len(), 66);
        assert!(hex.starts_with("0xffffffffffffffff"), "got {hex}");
    }

    // ─── parse_witness_json ──────────────────────────────────────────────────

    #[test]
    fn a_witness_file_parses_with_its_declared_arity() {
        let json = r#"{"num_public_signals": 2, "witness": ["1", "7", "9"]}"#;
        let (witness, arity) = parse_witness_json(json).unwrap();
        assert_eq!(arity, Some(2));
        assert_eq!(
            witness,
            vec![
                Bn254Fr::from(1u64),
                Bn254Fr::from(7u64),
                Bn254Fr::from(9u64)
            ]
        );
    }

    #[test]
    fn a_witness_file_without_an_arity_still_parses() {
        let (witness, arity) = parse_witness_json(r#"{"witness": ["1"]}"#).unwrap();
        assert_eq!(arity, None);
        assert_eq!(witness.len(), 1);
    }

    /// The failing index has to be in the message: a 16,928-element witness
    /// with one bad entry is not searchable by hand.
    #[test]
    fn a_witness_file_with_a_bad_element_names_the_index() {
        let json = r#"{"witness": ["1", "not-a-number"]}"#;
        let err = parse_witness_json(json).unwrap_err();
        assert!(err.to_string().contains("witness[1]"), "got: {err}");
    }

    #[test]
    fn malformed_witness_json_is_refused() {
        assert!(parse_witness_json("{{{ not json").is_err());
    }
}
