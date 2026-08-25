use antech_kdf_format::parse_hash;
use rand::RngCore;

#[test]
fn parse_arbitrary_utf8_never_panics() {
    let mut rng = rand::thread_rng();
    for _ in 0..512 {
        let len = (rng.next_u32() % 4096) as usize;
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        for b in &mut bytes {
            if *b == 0 {
                *b = b'$';
            }
        }
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = parse_hash(s);
        }
    }
}

#[test]
fn rejects_huge_encoded_string() {
    let huge = format!("${}", "a".repeat(9000));
    assert!(parse_hash(&huge).is_err());
}

#[test]
fn rejects_duplicate_parameters() {
    let dup = "$antech$v2$m=16384,m=16384,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
    assert!(parse_hash(dup).is_err());
}

#[test]
fn rejects_out_of_range_memory_in_hash() {
    let low = "$antech$v2$m=512,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff$0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
    assert!(parse_hash(low).is_err());
}
