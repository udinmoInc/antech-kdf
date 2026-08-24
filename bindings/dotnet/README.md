# Antech KDF .NET Binding

Uses `DllImport` / `LibraryImport` P/Invoke calling `antech-kdf-ffi`.

```csharp
using Antech;

var hash = AntechKdf.Hash("hello");
bool valid = AntechKdf.Verify("hello", hash);
```
