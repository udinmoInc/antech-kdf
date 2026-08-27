//! Hash format encoding and parsing crate.

pub mod encoder;
pub mod parser;

pub use encoder::encode_hash;
pub use parser::parse_hash;

#[cfg(test)]
mod tests {
    use super::*;
    use antech_kdf_types::{AntechConfig, GraphKind};

    #[test]
    fn encode_parse_roundtrip() {
        let cfg = AntechConfig::builder()
            .memory_mib(16)
            .salt_length(16)
            .fan_in(2)
            .graph(GraphKind::CombinedFrontier)
            .output_length(32)
            .build()
            .unwrap();
        let salt = [0x42u8; 16];
        let digest = [0x11u8; 32];
        let encoded = encode_hash(&cfg, &salt, &digest).unwrap();
        assert!(encoded.starts_with("$antech$v2$"));
        let parsed = parse_hash(&encoded).unwrap();
        assert_eq!(parsed.memory_kib, 16 * 1024);
        assert_eq!(parsed.fan_in, 2);
        assert_eq!(parsed.graph, GraphKind::CombinedFrontier);
        assert_eq!(parsed.salt, salt.to_vec());
        assert_eq!(parsed.digest, digest.to_vec());
    }

    #[test]
    fn legacy_v1_rejected() {
        let legacy = "$antech$v1$m=16384,s=16,t=1,p=1,b=32,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
        assert!(parse_hash(legacy).is_err());
    }

    #[test]
    fn rejects_oversized_salt_hex_before_decode() {
        let oversized = "aa".repeat(10_000);
        let encoded = format!(
            "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32${oversized}$0011223344556677889900aabbccddee0011223344556677889900aabbccddee"
        );
        let err = parse_hash(&encoded).unwrap_err();
        assert!(matches!(err, antech_kdf_types::KdfError::Encoding(_)));
    }

    #[test]
    fn rejects_invalid_salt_length_param() {
        let encoded = "$antech$v2$m=16384,s=999,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddee0011223344556677889900aabbccddee";
        assert!(parse_hash(encoded).is_err());
    }

    #[test]
    fn rejects_non_ascii_hex_without_panic() {
        // Multi-byte UTF-8 in the salt field used to panic in hex_decode via s[i..i+2]
        // crossing a char boundary (fuzz finding R14).
        // 30 ASCII hex chars + one 2-byte UTF-8 char (ß) = 32 bytes (== s=16 hex width).
        let salt = format!("{}{}", "a".repeat(30), "ß");
        assert_eq!(salt.len(), 32);
        let digest = "bb".repeat(32);
        let encoded = format!("$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32${salt}${digest}");
        let result = std::panic::catch_unwind(|| parse_hash(&encoded));
        assert!(result.is_ok(), "parse_hash must not panic on non-ascii hex");
        assert!(result.unwrap().is_err(), "non-ascii hex must be rejected");
    }

    #[test]
    fn rejects_duplicate_m_param() {
        let encoded = "$antech$v2$m=16384,m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
        assert!(parse_hash(encoded).is_err());
    }

    #[test]
    fn encode_optional_sk_and_adl_markers() {
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .secret_required(true)
            .associated_data_length(9)
            .build()
            .unwrap();
        let salt = [0x11u8; 16];
        let digest = [0x22u8; 32];
        let encoded = encode_hash(&cfg, &salt, &digest).unwrap();
        assert!(encoded.contains(",sk=1"));
        assert!(encoded.contains(",adl=9"));
        let parsed = parse_hash(&encoded).unwrap();
        assert!(parsed.secret_required);
        assert_eq!(parsed.associated_data_length, Some(9));
    }

    #[test]
    fn legacy_without_sk_adl_parses_as_unused() {
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .build()
            .unwrap();
        let salt = [0x33u8; 16];
        let digest = [0x44u8; 32];
        let encoded = encode_hash(&cfg, &salt, &digest).unwrap();
        assert!(!encoded.contains(",sk="));
        assert!(!encoded.contains(",adl="));
        let parsed = parse_hash(&encoded).unwrap();
        assert!(!parsed.secret_required);
        assert_eq!(parsed.associated_data_length, None);
    }

    fn digest32_hex() -> String {
        "ab".repeat(32)
    }

    fn salt16_hex() -> String {
        "cd".repeat(16)
    }

    #[test]
    fn rejects_malformed_prefix_and_version() {
        assert!(parse_hash("").is_err());
        assert!(parse_hash("$bcrypt$").is_err());
        assert!(parse_hash("$antech$").is_err());
        assert!(parse_hash("$antech$v3$m=1024,s=16,b=32,f=2,g=3,l=32$x$y").is_err());
        assert!(parse_hash(&format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32${}${}",
            salt16_hex(),
            digest32_hex()
        ))
        .is_ok());
    }

    #[test]
    fn rejects_invalid_hex_nibbles() {
        let bad_salt = format!("{}GG", "aa".repeat(15));
        let encoded = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32${bad_salt}${}",
            digest32_hex()
        );
        assert!(parse_hash(&encoded).is_err());
    }

    #[test]
    fn rejects_odd_length_hex() {
        let odd = format!("{}a", "bb".repeat(15)); // 31 chars
        let encoded = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32${odd}${}",
            digest32_hex()
        );
        assert!(parse_hash(&encoded).is_err());
    }

    #[test]
    fn rejects_duplicate_sk_and_adl() {
        let base = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32,sk=1,sk=1${}${}",
            salt16_hex(),
            digest32_hex()
        );
        assert!(parse_hash(&base).is_err());
        let adl = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32,adl=0,adl=0${}${}",
            salt16_hex(),
            digest32_hex()
        );
        assert!(parse_hash(&adl).is_err());
    }

    #[test]
    fn rejects_oversized_encoded_string() {
        let huge = format!("${}", "a".repeat(9000));
        assert!(parse_hash(&huge).is_err());
    }

    #[test]
    fn rejects_salt_and_output_boundary_params() {
        // s=7 below min
        let low_s = format!(
            "$antech$v2$m=1024,s=7,b=32,f=2,g=3,l=32${}${}",
            "aa".repeat(7),
            digest32_hex()
        );
        assert!(parse_hash(&low_s).is_err());
        // l=7 below min
        let low_l = format!(
            "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=7${}${}",
            salt16_hex(),
            "aa".repeat(7)
        );
        assert!(parse_hash(&low_l).is_err());
        // f=1 / f=9
        let low_f = format!(
            "$antech$v2$m=1024,s=16,b=32,f=1,g=3,l=32${}${}",
            salt16_hex(),
            digest32_hex()
        );
        assert!(parse_hash(&low_f).is_err());
        let high_f = format!(
            "$antech$v2$m=1024,s=16,b=32,f=9,g=3,l=32${}${}",
            salt16_hex(),
            digest32_hex()
        );
        assert!(parse_hash(&high_f).is_err());
        // b=24 not power of two
        let bad_b = format!(
            "$antech$v2$m=1024,s=16,b=24,f=2,g=3,l=32${}${}",
            salt16_hex(),
            digest32_hex()
        );
        assert!(parse_hash(&bad_b).is_err());
    }

    #[test]
    fn salt_length_max_roundtrip() {
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(256)
            .output_length(32)
            .build()
            .unwrap();
        let salt = [0x5Au8; 256];
        let digest = [0xA5u8; 32];
        let encoded = encode_hash(&cfg, &salt, &digest).unwrap();
        let parsed = parse_hash(&encoded).unwrap();
        assert_eq!(parsed.salt, salt.to_vec());
        assert_eq!(parsed.salt_len, 256);
    }
}
