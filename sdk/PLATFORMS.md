# SDK platform notes

| Platform | Status |
|---|---|
| Windows x64 | `cdylib` → `antech_kdf_ffi.dll` |
| Linux x64 / aarch64 | `libantech_kdf_ffi.so` |
| macOS x64 / arm64 | `libantech_kdf_ffi.dylib` |
| Android | `cargo ndk -t arm64-v8a -o sdk/native/android build -p antech-kdf-ffi --release` |
| iOS | build staticlib / XCFramework with `cargo lipo` or `cross`; SwiftPM links `antech_kdf_ffi` |
| Server (containers) | ship matching glibc/musl `.so` next to the language package or set `ANTECH_KDF_LIB` |

## Thread safety

All FFI entry points are thread-safe and stateless. Concurrent `hash` / `verify` share an internal resource scheduler.

## Async / non-blocking

Hashing is CPU- and memory-bound. In async runtimes, call from a worker thread / `spawn_blocking` / `Task.Run` so event loops are not blocked. The API itself is synchronous.

## Memory ownership

- Encoded hashes returned by FFI are Rust-allocated; free with `antech_free` (language wrappers do this automatically).
- Config / rehash policy structs are caller-owned POD.
- Passwords are never retained after the call returns.

## Binary distribution

Language packages either:

1. Document linking against a prebuilt `sdk/native` artifact from CI release uploads, or
2. Set `ANTECH_KDF_LIB` / `PATH` / `LD_LIBRARY_PATH` / `java.library.path` to the library directory.

Publish workflows upload per-OS native artifacts on `v*` tags (`.github/workflows/release-sdk.yml`).
