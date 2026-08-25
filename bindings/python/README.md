# Antech KDF — Python Language Bindings

Python bindings for Antech KDF via `ctypes` / C FFI.

```python
from antech_kdf import hash_password, verify_password, needs_rehash

stored = hash_password("secret_password")
assert verify_password("secret_password", stored)
assert not needs_rehash(stored)
```

For official repository updates, visit [Antech KDF on GitHub](https://github.com/udinmoInc/antech-kdf).
