# ASan + UB-checks validation report — Antech KDF

**Combined verdict: PASS**

| Check | Verdict |
|---|---|
| AddressSanitizer (ASan) | **PASS** |
| Rust UB checks (`-Zub-checks`) | **PASS** |
| LLVM UBSan (`-Zsanitizer=undefined`) | **BLOCKED** |

CI: [workflow run 33140604849](https://github.com/udinmoInc/antech-kdf/actions/runs/33140604849) on commit `402d9d3`.

This campaign targets memory safety (ASan) and undefined behavior (Rust
`-Zub-checks` with `-Zbuild-std`) on `x86_64-unknown-linux-gnu`. LLVM
`-Zsanitizer=undefined` is **not supported** on current rustc — see
`skipped.csv`. It does **not** change KDF algorithms, public API, v2 encoding,
or canonical parameters.

## Results

- **ASan:** 97 production tests (debug + release) + 2 reference tests per profile; zero sanitizer findings.
- **UB checks:** same matrix under `-Zub-checks`; zero panics from UB detection.
- **Miri** (separate job, same workflow): PASS on pure-Rust production crates.

## Verdict key

| Label | Meaning |
|---|---|
| PASS | Sanitizer/check job executed; no findings / test failures |
| FAIL | Sanitizer reported defect or test failure |
| BLOCKED | Tool unavailable on host (toolchain/OS) |
| NOT RUN | Job did not complete or artifact missing |
| NOT APPLICABLE | Target excluded with documented reason |

## Production coverage

- `antech-kdf-types`, `antech-kdf-format`, `antech-kdf-core`, `antech-kdf`, `antech-kdf-ffi`
- Unit + integration tests (`--lib --tests`): parser/property, config boundaries, hash/verify, secret/AD, scheduler, FFI, conformance vectors
- Debug and release-like (`--release`) profiles

## Sensitive areas exercised

v2 parser/hex validation, config bounds, scheduler acquire/release/queue_limit, FFI ownership/panic containment, binary passwords, SecretBytes/AD, engine prefetch `unsafe` (via derives), serde conformance JSON.

## Failures / regressions

None. See `regressions.csv`. No suppressions added to silence findings.

## Prior CI note

Run [33104978058](https://github.com/udinmoInc/antech-kdf/actions/runs/33104978058) failed due to (1) LLVM UBSan unsupported and (2) ASan script `grep`/`pipefail` bug — both fixed in `402d9d3`.
