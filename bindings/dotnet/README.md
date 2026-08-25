# Antech KDF — .NET Language Bindings

C# / .NET bindings for Antech KDF via `LibraryImport` P/Invoke calling `antech-kdf-ffi`.

```csharp
using Antech;

var hash = AntechKdf.Hash("secret_password");
bool valid = AntechKdf.Verify("secret_password", hash);
```

For official repository updates, visit [Antech KDF on GitHub](https://github.com/udinmoInc/antech-kdf).
