# Antech KDF SDK

All language packages are thin wrappers over the **canonical Rust core** via `antech-kdf-ffi`.
No language reimplements the KDF.

| Package | Path | Install |
|---|---|---|
| Rust | `crates/antech-kdf` | `cargo add antech-kdf` |
| C | `bindings/c` | link `libantech_kdf` + `antech_kdf.h` |
| C++ | `bindings/cpp` | header over C ABI |
| Go | `bindings/go` | `go get` / cgo |
| Python | `bindings/python` | `pip install antech-kdf` |
| Node/TS | `bindings/node` | `npm install antech-kdf` |
| Java | `bindings/java` | Maven/Gradle |
| Kotlin | `bindings/kotlin` | same artifact as Java |
| Swift | `bindings/swift` | SwiftPM |
| .NET | `bindings/dotnet` | `dotnet add package Antech.Kdf` |

Authoritative version: repo-root [`VERSION`](../VERSION). Sync with `sdk/scripts/sync-versions.py`.

Conformance vectors: [`conformance/`](conformance/). Native build: `sdk/scripts/build-native.*`.
