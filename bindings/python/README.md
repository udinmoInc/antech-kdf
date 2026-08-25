# Antech KDF — Python

Thin `ctypes` wrapper. Build the native library first:

```powershell
.\sdk\scripts\build-native.ps1
pip install -e .\bindings\python
python -c "import antech_kdf; print(antech_kdf.hash('x'))"
```

API: `hash`, `verify`, `needs_rehash`, `hash_with_config`, `needs_rehash_with_policy`, `hash_with_config_and_salt`.
