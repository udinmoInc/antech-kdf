# Antech KDF — Nim

Thin `importc` wrapper over `bindings/c/antech_kdf.h`.

```bash
./sdk/scripts/build-native.sh
nim c -r bindings/nim/examples/basic.nim
```

Links `-lantech_kdf` from `sdk/native` / `target/release`.
