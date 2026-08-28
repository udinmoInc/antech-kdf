# ASan + UB-checks validation report — Antech KDF

**Combined verdict: NOT_RUN** (pending Ubuntu CI after script fix)

| Check | Verdict |
|---|---|
| AddressSanitizer (ASan) | NOT_RUN |
| Rust UB checks (`-Zub-checks`) | NOT_RUN |
| LLVM UBSan (`-Zsanitizer=undefined`) | **BLOCKED** (unsupported on rustc) |

Windows local host: **BLOCKED** for `-Zsanitizer=address` and `-Zub-checks`.

CI run [33104978058](https://github.com/udinmoInc/antech-kdf/actions/runs/33104978058) (commit `6558e4e`):
- ASan: all production + reference tests **passed**; job failed due to `count_passed` `grep`/`pipefail` bug (fixed).
- LLVM UBSan: **BLOCKED** — rustc rejects `-Zsanitizer=undefined`.

See `summary.md`, `asan.csv`, `ubsan.csv`, `skipped.csv`, `regressions.csv`, and `logs/` after the next CI run.
