# Python bindings

Thin wrappers over `antech-kdf-ffi`.

```python
from antech_kdf import hash_password, verify_password, needs_rehash

stored = hash_password("secret_password")
assert verify_password("secret_password", stored)
assert not needs_rehash(stored)
```
