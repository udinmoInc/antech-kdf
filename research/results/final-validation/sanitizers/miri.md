# Miri (local host)

**Status:** BLOCKED

Reason: cargo +nightly-msvc miri setup failed — linker `link.exe` not found (VS Build Tools missing).

CI owns the PASS/FAIL verdict via .github/workflows/sanitizers.yml on `ubuntu-latest`.

Excluded locally and in CI notes:
- antech-kdf-ffi (unsafe C ABI)
- CUDA / GPU attackers
