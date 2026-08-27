# ASan / UBSan (local host)

**Status:** BLOCKED

Reason: `-Zsanitizer=address|undefined` requires Linux nightly + `build-std`. Not supported on this Windows GNU/MSVC host without VS linker.

CI: .github/workflows/sanitizers.yml jobs `asan` and `ubsan`.
