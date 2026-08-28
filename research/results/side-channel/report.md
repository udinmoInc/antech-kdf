# Side-channel analysis report — Antech KDF v5 (production)

**Combined verdict: PASS**

Frozen production implementation; no algorithm, API, v2 format, or parameter changes.

CI: [validation run 33148612384](https://github.com/udinmoInc/antech-kdf/actions/runs/33148612384) (job `side-channel-linux` **success**).

## Platforms

| Layer | Windows | Linux (Ubuntu CI) |
|---|---|---|
| Wall-clock timing | **MEASURED** (`timing-windows.csv`) | **MEASURED** (`timing-linux.csv`) |
| PMU / cache / branch HW counters | **BLOCKED** (no local perf) | **BLOCKED** (`perf-probe.log`) |
| Branch static audit | **MODELED** (`branch-analysis.csv`) | same |
| FFI / contention | **MEASURED** | **MEASURED** |

## Constant-time scope (precise claims)

| Claim | Scope | Evidence |
|---|---|---|
| Constant-time digest compare | `core_verify_with_inputs` final step | `subtle::ConstantTimeEq` (**MEASURED**) |
| Not constant-time w.r.t. password | Full derive path | Data-dependent memory-hard walk (**MODELED**, accepted) |
| Not constant-time parse | Public encoded hash | Variable-time hex decode (**MEASURED**) |

Do **not** describe the KDF as globally constant-time.

## Timing: correct vs wrong password (MEASURED)

| Host | median ratio | Welch t | Verdict |
|---|---|---|---|
| Windows (80 samples, 1 MiB) | 0.998 | 0.41 | no shortcut |
| Linux (40 samples, 1 MiB CI) | 1.000 | 0.90 | no shortcut |

Wrong password always runs full derive; digest compared with `ct_eq` after derive completes.

## Linux PMU / cache analysis (BLOCKED — NOT RUN)

`perf stat` on GitHub-hosted `ubuntu-latest` returns `<not supported>` / zero for `instructions` and hardware cache events even with `sudo` and `kernel.perf_event_paranoid=-1`. See `perf-probe.log`.

| Item | Status |
|---|---|
| Per-scenario PMU rows (`cache-analysis.csv`) | **BLOCKED** |
| Statistical PMU pairs P01–P07 (`cache-comparison.csv`) | **NOT RUN** |
| Inferred PMU PASS | **No** — limitation documented honestly |

PMU analysis requires a bare-metal or self-hosted Linux host with working perf events. The CI job still validates Linux wall-clock timing and reproduces the Windows T01 conclusion.

## Practical attack assessment

| Vector | Result |
|---|---|
| Online verify timing shortcut (correct vs wrong password) | **Not observed** (Windows + Linux) |
| PMU cache-miss oracle on password bytes | **NOT RUN** (PMU BLOCKED on CI) |
| Parse malformed hash faster than verify | **Yes** — public encoding only (expected) |
| Missing secret / AD API misuse oracle | **Yes** — pre-derive fast path (expected) |
| Cross-tenant cache probe on memory walk | **Theoretical** (MODELED; intentional graph design) |
| Scheduler queue as password oracle | **No** (MEASURED) |

## Regressions

None. See `regressions.csv`. No production code changes required.

## Reproduction

```bash
# Full timing campaign (Windows or Linux)
cargo run --manifest-path research/code/Cargo.toml --release \
  -p antech-kdf-research --example side_channel_runner

# Linux PMU (requires working perf on host)
./scripts/side_channel_perf_linux.sh
./scripts/side_channel_finalize.sh
```
