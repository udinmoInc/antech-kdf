# Antech KDF — Zig

Thin `@cImport` wrapper over `bindings/c/antech_kdf.h`.

```bash
./sdk/scripts/build-native.sh
cd bindings/zig && zig build run
```

Link against `sdk/native` (or set library search path). Crypto stays in the Rust cdylib.
