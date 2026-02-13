//! Utility functions for proof generation

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;

/// Convert decimal string to field element (snarkjs format)
///
/// Accepts decimal string representation of field element (e.g., "123456")
/// This is the native format used by snarkjs witness output.
pub fn decimal_to_field(decimal_str: &str) -> Result<Bn254Fr, String> {
    // Parse as BigUint
    let big_uint = BigUint::parse_bytes(decimal_str.as_bytes(), 10)
        .ok_or_else(|| format!("Failed to parse decimal string: {}", decimal_str))?;

    // Convert to bytes (little-endian for arkworks)
    let bytes = big_uint.to_bytes_le();

    // Convert to field element (with modular reduction)
    Ok(Bn254Fr::from_le_bytes_mod_order(&bytes))
}

/// Convert hex string to field element
///
/// Expects little-endian hex string (0x + 64 hex chars)
pub fn hex_to_field(hex_str: &str) -> Result<Bn254Fr, String> {
    // Remove 0x prefix if present
    let hex_clean = if let Some(stripped) = hex_str.strip_prefix("0x") {
        stripped
    } else {
        hex_str
    };

    // Pad to 64 chars if needed (handles odd-length hex)
    let hex_padded = if hex_clean.len() % 2 == 1 {
        format!("0{hex_clean}")
    } else {
        hex_clean.to_string()
    };

    // Decode hex to bytes (little-endian)
    let bytes = hex::decode(&hex_padded).map_err(|e| format!("Failed to decode hex: {e}"))?;

    // Convert to field element (arkworks expects little-endian)
    Ok(Bn254Fr::from_le_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_to_field() {
        let decimal = "1";
        let field = decimal_to_field(decimal).unwrap();
        assert_eq!(field, Bn254Fr::from(1u64));
    }

    #[test]
    fn test_decimal_to_field_large() {
        let decimal = "12345678901234567890";
        let result = decimal_to_field(decimal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decimal_to_field_zero() {
        let decimal = "0";
        let field = decimal_to_field(decimal).unwrap();
        assert_eq!(field, Bn254Fr::from(0u64));
    }

    #[test]
    fn test_decimal_to_field_invalid() {
        let decimal = "not_a_number";
        let result = decimal_to_field(decimal);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to parse decimal string"));
    }

    #[test]
    fn test_hex_to_field() {
        let hex = "0x0100000000000000000000000000000000000000000000000000000000000000";
        let field = hex_to_field(hex).unwrap();
        assert_eq!(field, Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_to_field_no_prefix() {
        let hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let field = hex_to_field(hex).unwrap();
        assert_eq!(field, Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_to_field_zero() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let field = hex_to_field(hex).unwrap();
        assert_eq!(field, Bn254Fr::from(0u64));
    }

    #[test]
    fn test_hex_to_field_max_value() {
        let hex = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = hex_to_field(hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_to_field_odd_length() {
        let hex = "0x1";
        let field = hex_to_field(hex).unwrap();
        assert_eq!(field, Bn254Fr::from(1u64));
    }

    #[test]
    fn test_hex_to_field_invalid_hex() {
        let hex = "0xGGGG";
        let result = hex_to_field(hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode hex"));
    }

    #[test]
    fn test_hex_conversion_roundtrip() {
        let original_value = 12345u64;
        let field_original = Bn254Fr::from(original_value);

        let mut bytes = vec![0u8; 32];
        bytes[0] = (original_value & 0xFF) as u8;
        bytes[1] = ((original_value >> 8) & 0xFF) as u8;
        bytes[2] = ((original_value >> 16) & 0xFF) as u8;
        bytes[3] = ((original_value >> 24) & 0xFF) as u8;

        let hex_str = format!("0x{}", hex::encode(&bytes));
        let field_converted = hex_to_field(&hex_str).unwrap();

        assert_eq!(field_original, field_converted);
    }

    #[test]
    fn test_witness_array_conversion() {
        let witness_hex = [
            "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
            "0x0200000000000000000000000000000000000000000000000000000000000000".to_string(),
            "0x0300000000000000000000000000000000000000000000000000000000000000".to_string(),
        ];

        let witness: Result<Vec<Bn254Fr>, String> = witness_hex[..]
            .iter()
            .map(|hex| hex_to_field(hex))
            .collect();

        assert!(witness.is_ok());
        let witness = witness.unwrap();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], Bn254Fr::from(1u64));
        assert_eq!(witness[1], Bn254Fr::from(2u64));
        assert_eq!(witness[2], Bn254Fr::from(3u64));
    }
}
