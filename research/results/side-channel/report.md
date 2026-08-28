# Side-channel analysis report — Antech KDF v5 (production)

**Verdict: PASS**

Research-only validation of the **frozen** production implementation. No algorithm, API, v2 format, or parameter changes were made.

## Scope of constant-time claims

| Claim | Scope | Evidence |
|---|---|---|
| Constant-time **digest comparison** | `core_verify_with_inputs` final step | `subtle::ConstantTimeEq::ct_eq` on equal-length digests (**MEASURED** via source + timing) |
| **Not** constant-time w.r.t. password | Full `hash`/`verify` derive | Memory-hard walk is intentionally data-dependent (**MODELED**, accepted) |
| **Not** constant-time parse | `parse_hash` on public encoding | Variable-time hex decode on attacker-controlled **public** string (**MEASURED**) |

Do **not** describe the KDF as globally constant-time.

## Statistical timing (MEASURED)

Profile: `80` derive samples, `800` fast-path samples per comparison on **windows**.

Primary result **T01** (correct vs wrong password, 1 MiB verify):
- median correct: 3377700 ns
- median wrong: 3385400 ns
- ratio: 0.9977
- Welch t: 0.411
- significant (derive): no

Fast-path oracles (**expected**, not password-byte leaks):
- Malformed / truncated encodings reject before derive (T07, T08).
- Missing secret / AD length mismatch reject before derive (T09, T10) — API misuse oracle, not offline password guessing.

## Branch / memory analysis

See `branch-analysis.csv` (9 rows). Highlights:
- Digest compare: constant-time primitive post-derive.
- Engine graph: state-dependent indices + x86 prefetch hints — cache timing is a **theoretical** shared-core concern, not a verify shortcut.
- No branch on `password == stored` before derive completes.

## FFI boundary (MEASURED)

3 FFI rows in `ffi.csv`. Overhead is ABI marshalling; no extra secret-dependent branches vs Rust.

## Contention (MEASURED)

1 contention scenario(s). Background hashing may increase verify latency via global scheduler; does not reveal password correctness.

## Cache / PMU

**BLOCKED** on this host — hardware counters require Linux `perf` (see CI job).

## Practical attack assessment

| Vector | Assessment |
|---|---|
| Online password guess via verify timing shortcut | **Not observed** — wrong password pays full derive |
| Parse malformed hash faster than verify | **Yes** — public encoding only |
| Missing secret faster than wrong password | **Yes** — documented API precondition |
| Cross-tenant cache probing on memory walk | **Theoretical** — requires shared hardware + co-resident attacker |
| Scheduler queue as correctness oracle | **No** |

## Regressions

See `regressions.csv`. No implementation defects requiring code changes in this campaign.

## Reproduction

```bash
cargo run --manifest-path research/code/Cargo.toml --release \
  -p antech-kdf-research --example side_channel_runner
```

Linux CI: `.github/workflows/validation.yml` job `side-channel-linux` (perf counters, `ANTECH_SIDECHANNEL_PROFILE=ci`).
