# Antech KDF — C ABI

Header: [`antech_kdf.h`](antech_kdf.h). Implementation: `crates/antech-kdf-ffi` (`cdylib`).

```bash
cargo build -p antech-kdf-ffi --release
# link libantech_kdf_ffi + include antech_kdf.h
```

Ownership: free hash strings with `antech_free`. Thread-safe / stateless. Prefer `*_bytes` for binary passwords.
