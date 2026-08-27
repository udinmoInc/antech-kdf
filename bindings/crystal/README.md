# Antech KDF — Crystal

Thin `lib` binding over the C ABI.

```bash
./sdk/scripts/build-native.sh
LIBRARY_PATH=sdk/native:target/release crystal run bindings/crystal/examples/basic.cr
```

On Windows, point the linker at `sdk/native` (or set `ANTECH_KDF_LIB` / PATH to the DLL).
