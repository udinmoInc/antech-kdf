#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    antech_kdf_fuzz_harness::run_ffi(data).expect("ffi invariant");
});
