use ark_ff::PrimeField;
use num_bigint::BigUint;

/// Parse a decimal string into any `PrimeField` element (snarkjs native wire format).
pub fn from_decimal_str<F: PrimeField>(s: &str) -> Result<F, String> {
    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| format!("Failed to parse decimal string: {s}"))?;
    Ok(F::from_le_bytes_mod_order(&n.to_bytes_le()))
}

/// Parse a little-endian hex string (`0x…` prefix optional) into any `PrimeField` element.
pub fn from_hex_le<F: PrimeField>(hex: &str) -> Result<F, String> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = if stripped.len() % 2 == 1 {
        format!("0{stripped}")
    } else {
        stripped.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("Failed to decode hex: {e}"))?;
    Ok(F::from_le_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;

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

    #[test]
    fn test_decimal_leading_zeros() {
        let a = from_decimal_str::<Bn254Fr>("0001").unwrap();
        let b = from_decimal_str::<Bn254Fr>("1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_hex_le_one() {
        let hex = "0x0100000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(from_hex_le::<Bn254Fr>(hex).unwrap(), Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_le_one_no_prefix() {
        let hex = "0100000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(from_hex_le::<Bn254Fr>(hex).unwrap(), Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_le_zero() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(from_hex_le::<Bn254Fr>(hex).unwrap(), Bn254Fr::from(0u64));
    }

    #[test]
    fn test_hex_le_max_value() {
        let hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(from_hex_le::<Bn254Fr>(hex).is_ok());
    }

    #[test]
    fn test_hex_le_odd_length() {
        assert_eq!(from_hex_le::<Bn254Fr>("0x1").unwrap(), Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_le_invalid() {
        let err = from_hex_le::<Bn254Fr>("0xGGGG").unwrap_err();
        assert!(err.contains("Failed to decode hex"));
    }

    #[test]
    fn test_hex_le_roundtrip() {
        let val = 12345u64;
        let mut bytes = vec![0u8; 32];
        bytes[0] = (val & 0xFF) as u8;
        bytes[1] = ((val >> 8) & 0xFF) as u8;
        bytes[2] = ((val >> 16) & 0xFF) as u8;
        bytes[3] = ((val >> 24) & 0xFF) as u8;
        let hex = format!("0x{}", hex::encode(&bytes));
        assert_eq!(from_hex_le::<Bn254Fr>(&hex).unwrap(), Bn254Fr::from(val));
    }

    #[test]
    fn test_decimal_hex_consistency() {
        let a = from_decimal_str::<Bn254Fr>("12345").unwrap();
        let b = from_hex_le::<Bn254Fr>(
            "0x3930000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_batch_hex_conversion() {
        let inputs = [
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "0x0200000000000000000000000000000000000000000000000000000000000000",
            "0x0300000000000000000000000000000000000000000000000000000000000000",
        ];
        let fields: Vec<Bn254Fr> = inputs.iter().map(|h| from_hex_le(h).unwrap()).collect();
        assert_eq!(fields[0], Bn254Fr::from(1u64));
        assert_eq!(fields[1], Bn254Fr::from(2u64));
        assert_eq!(fields[2], Bn254Fr::from(3u64));
    }
}
