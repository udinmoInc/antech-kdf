# Antech KDF — Swift

SwiftPM package wrapping the C ABI (`libantech_kdf_ffi`). Build the native library and ensure the linker can find it (`LIBRARY_PATH` / Xcode search paths). iOS: produce an XCFramework via `cargo lipo` / `cargo-ndk` style workflows documented in `sdk/README.md`.
