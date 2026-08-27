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
| PHP | `bindings/php` | Composer + `ext-ffi` |
| Ruby | `bindings/ruby` | `gem install ffi` / gemspec |
| Dart | `bindings/dart` | `dart pub get` |
| Perl | `bindings/perl` | `cpanm FFI::Platypus` |
| R | `bindings/r` | `Rscript build_shim.R` + source |
| Lua | `bindings/lua` | LuaJIT `require("antech_kdf")` |
| Zig | `bindings/zig` | `zig build` |
| Crystal | `bindings/crystal` | `crystal run` |
| Nim | `bindings/nim` | `nim c` |
| Julia | `bindings/julia` | `julia` + `include` |
| Haskell | `bindings/haskell` | `cabal run` |

Authoritative version: repo-root [`VERSION`](../VERSION).  
Package metadata (author, email, license, URLs): [`package-meta.json`](package-meta.json) — applied to **manifests only**. Binding sources keep a `VERSION` constant for fallbacks.

```bash
python sdk/scripts/sync-versions.py
python sdk/scripts/sync-versions.py --list
```

Conformance vectors: [`conformance/`](conformance/). Native build: `sdk/scripts/build-native.*`.
