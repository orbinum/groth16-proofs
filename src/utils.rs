// Backward-compatible shims for decimal_to_field and hex_to_field.
// Logic lives in field.rs as generic functions.
use crate::field::{from_decimal_str, from_hex_le};
use ark_bn254::Fr as Bn254Fr;

pub fn decimal_to_field(s: &str) -> Result<Bn254Fr, String> {
    from_decimal_str::<Bn254Fr>(s)
}

pub fn hex_to_field(hex: &str) -> Result<Bn254Fr, String> {
    from_hex_le::<Bn254Fr>(hex)
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

    #[test]
    fn test_decimal_hex_consistency() {
        // decimal_to_field and hex_to_field must produce the same field element
        // for the same numeric value.
        let decimal = decimal_to_field("12345").unwrap();
        let hex =
            hex_to_field("0x3930000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert_eq!(decimal, hex);
    }

    #[test]
    fn test_decimal_to_field_empty_string() {
        let result = decimal_to_field("");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to parse decimal string"));
    }

    #[test]
    fn test_decimal_to_field_leading_zeros() {
        // "0001" should parse the same as "1"
        let a = decimal_to_field("0001").unwrap();
        let b = decimal_to_field("1").unwrap();
        assert_eq!(a, b);
    }
}
