# Antech KDF — Julia

Thin `ccall` wrapper. No package install required for local use:

```bash
./sdk/scripts/build-native.sh
julia bindings/julia/examples/basic.jl
```

Set `ANTECH_KDF_LIB` to the cdylib path if discovery fails.
