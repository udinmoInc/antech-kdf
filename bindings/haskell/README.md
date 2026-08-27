# Antech KDF — Haskell

Thin `foreign import ccall` wrapper.

```bash
./sdk/scripts/build-native.sh
cd bindings/haskell && cabal run antech-basic
```

Ensure the linker can see `sdk/native` (`LIBRARY_PATH` / `extra-lib-dirs`).
