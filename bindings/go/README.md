# Antech KDF — Go

CGO wrapper over `libantech_kdf_ffi`. Build the native library first:

```bash
./sdk/scripts/build-native.sh   # or build-native.ps1 on Windows
cd bindings/go
go test ./...
```

```go
h, _ := antech.Hash([]byte("password"))
ok, _ := antech.Verify([]byte("password"), h)
```

Examples: `examples/`.
