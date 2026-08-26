//! Malformed-input and boundary matrix for production API.

use antech_kdf::{hash, hash_with_config, needs_rehash, verify, AntechConfig, GraphKind};
use antech_kdf_types::KdfError;

fn assert_err<T>(r: Result<T, KdfError>) {
    assert!(r.is_err());
}

#[test]
fn password_edge_cases_hash_verify() {
    for pw in [
        &b""[..],
        &b"a"[..],
        &b"\x00"[..],
        &b"\xFF\xFE\x00\x01"[..],
        &vec![0xAB; 65536],
    ] {
        let encoded = hash(pw).expect("hash valid password shapes");
        assert!(verify(pw, &encoded).unwrap());
        assert!(!verify(b"wrong", &encoded).unwrap());
    }
}

#[test]
fn malformed_hash_matrix() {
    let cases = [
        "",
        "not_a_hash",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$aa$bb",
        "$antech$v3$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
        "$antech$v1$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
        "$unknown$v2$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
        "$antech$v2$m=invalid,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=99,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddee",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeffextra",
        "$antech$v2$m=16384,s=16,b=32,f=2,g=3,l=32,m=16384$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff",
    ];
    for h in cases {
        assert_err(verify("pw", h));
        assert_err(needs_rehash(h));
    }
}

#[test]
fn config_boundary_validation() {
    assert!(AntechConfig::builder().memory_kib(1024).build().is_ok());
    assert!(AntechConfig::builder().memory_kib(1023).build().is_err());
    assert!(AntechConfig::builder()
        .memory_kib(1_048_576)
        .build()
        .is_ok());
    assert!(AntechConfig::builder()
        .memory_kib(1_048_577)
        .build()
        .is_err());
    assert!(AntechConfig::builder().salt_length(8).build().is_ok());
    assert!(AntechConfig::builder().salt_length(7).build().is_err());
    assert!(AntechConfig::builder().block_size(16).build().is_ok());
    assert!(AntechConfig::builder().block_size(64).build().is_ok());
    assert!(AntechConfig::builder().block_size(15).build().is_err());
    assert!(AntechConfig::builder().block_size(128).build().is_err());
    assert!(AntechConfig::builder().fan_in(2).build().is_ok());
    assert!(AntechConfig::builder().fan_in(9).build().is_err());
}

#[test]
fn hash_deterministic_for_fixed_salt_config() {
    let cfg = AntechConfig::builder()
        .memory_mib(16)
        .salt_length(16)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let a = hash_with_config(b"deterministic", &cfg).unwrap();
    let b = hash_with_config(b"deterministic", &cfg).unwrap();
    assert_ne!(a, b, "random salt must differ each hash");
    assert!(verify(b"deterministic", &a).unwrap());
    assert!(verify(b"deterministic", &b).unwrap());
}
