# .NET bindings

P/Invoke / `LibraryImport` against `antech-kdf-ffi`.

```csharp
using Antech;

var hash = AntechKdf.Hash("secret_password");
bool ok = AntechKdf.Verify("secret_password", hash);
```
