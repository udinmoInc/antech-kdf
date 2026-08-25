# Antech KDF — C++

Header-only wrapper over [`../c/antech_kdf.h`](../c/antech_kdf.h). Link `libantech_kdf` (from `cargo build -p antech-kdf-ffi`).

```cpp
#include "antech_kdf.hpp"
auto h = antech::hash("password");
assert(antech::verify("password", h));
```

See `examples/` for hash / verify / config / rehash.
