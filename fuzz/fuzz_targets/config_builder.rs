#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let m = u16::from_le_bytes([data[0], data[1]]) as usize;
    let fan = 2 + (data[2] % 7) as u32;
    let b = match data[3] % 3 {
        0 => 16,
        1 => 32,
        _ => 64,
    };
    let _ = antech_kdf::AntechConfig::builder()
        .memory_kib(m.max(1))
        .fan_in(fan)
        .block_size(b)
        .build();
});
