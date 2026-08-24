# Antech KDF Python Binding

Uses `ctypes` or `cffi` to call `antech-kdf-ffi` C ABI.

```python
from antech_kdf import hash_password, verify_password, needs_rehash

stored = hash_password("hello")
assert verify_password("hello", stored)
assert not needs_rehash(stored)
```
