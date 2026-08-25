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
}
