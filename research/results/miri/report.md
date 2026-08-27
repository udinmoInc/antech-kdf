# Miri validation report — Antech production Rust

**Verdict: PASS**

Miri ran successfully on the Miri-compatible production paths using
`nightly-x86_64-pc-windows-gnu` with `-Zmiri-strict-provenance`. No
memory-safety or undefined-behavior failures were detected.

This campaign does **not** change KDF algorithms, the public API, v2 encoding,
secret/AD semantics, or canonical parameters.

## Verdict key

| Label | Meaning |
|---|---|
| PASS | Miri ran and reported no UB / test failures on selected suites |
| FAIL | Miri ran and found a defect or test failure |
| BLOCKED | Miri could not execute (toolchain/linker) |
| NOT APPLICABLE | Target excluded with documented reason |

## What ran

1. **types** — config / salt / block / fan-in / output / secret / AD / rehash boundaries
2. **format** — v2 encode/parse, malformed prefixes, invalid hex, duplicates, oversized inputs, salt max roundtrip
3. **format property** — UTF-8 never-panic (32 iters under Miri), huge/dup/range rejects
4. **core** — scheduler acquire/release, nested acquire, queue_limit=0, oversize request, permit error paths; **one** 1 MiB deterministic CombinedFrontier derive (prefetch `unsafe`)
5. **antech-kdf --lib** — malformed verify/rehash, oversized secret/AD, SecretBytes redaction

## Local environment notes

| Attempt | Result |
|---|---|
| `nightly-x86_64-pc-windows-msvc` `cargo miri setup` | **BLOCKED** — `LINK : fatal error LNK1181: cannot open input file 'kernel32.lib'` |
| `nightly-x86_64-pc-windows-gnu` | **PASS** — full campaign above |

CI (`.github/workflows/sanitizers.yml` + `scripts/miri_ci.sh`) remains Ubuntu-ready for reproducible Linux runs.

## Unsafe audit (summary)

Only production `unsafe` outside FFI is two x86_64 `_mm_prefetch` hints in
`antech-kdf-core` engine gather paths. Exercised by the Miri 1 MiB derive.
FFI remains **NOT APPLICABLE** for Miri (C ABI). Details: `unsafe-audit.md`.

## Failures / regressions

- **failures:** none (`failures.csv`)
- **product regressions added:** none (`regressions.csv`)
- **test harness:** added focused Miri boundary tests; marked multi-1MiB derives `#[cfg_attr(miri, ignore)]` for wall-time (still run under normal `cargo test`)

## Host gates after campaign

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace` | PASS |
| `cargo test --workspace` | PASS |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | PASS |

## Explicit non-claims

- Does **not** claim cryptographic security review.
- Does **not** claim FFI pointer contracts are Miri-proven.
- Multi-derive hash/verify under Miri were skipped for wall-time; those paths pass under normal tests and share the same engine code as the single Miri derive.
