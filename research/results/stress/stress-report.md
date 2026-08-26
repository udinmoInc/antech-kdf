# Antech KDF production stress report

**Verdict:** PASS

Host: windows / x86_64 / 12 logical CPUs / RAM hint Some(31.871105194091797) GiB

ResourcePolicy (production defaults): max_memory_kib=131072 max_active_jobs=64 queue_limit=256

Summary: all_idle=true unexpected_errors=0 panics=0 budget_violations=0 queue_limit_violations=0

## Mixed workload (70% valid verify / 20% wrong verify / 10% hash)

| secs | conc | ops | thrpt/s | p50 ms | p95 ms | p99 ms | rejects | unexpected | panics | peak_active | peak_q | peak_KiB | RSS peak | CPU% | idle | budget | q_ok |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|:---:|
| 10 | 1 | 106 | 10.54 | 93.4 | 100.3 | 123.0 | 0 | 0 | 0 | 1 | 0 | 16384 | 22425600 | 8.3 | true | true | true |
| 10 | 10 | 418 | 41.13 | 218.1 | 374.0 | 451.8 | 0 | 0 | 0 | 8 | 2 | 131072 | 130400256 | 65.2 | true | true | true |
| 10 | 32 | 448 | 41.84 | 727.7 | 1952.1 | 3062.4 | 0 | 0 | 0 | 8 | 24 | 131072 | 126660608 | 65.5 | true | true | true |
| 10 | 100 | 513 | 41.58 | 2363.5 | 6684.4 | 8983.5 | 0 | 0 | 0 | 8 | 92 | 131072 | 130854912 | 65.6 | true | true | true |
| 10 | 250 | 662 | 41.63 | 5900.8 | 11796.3 | 14650.7 | 0 | 0 | 0 | 8 | 242 | 131072 | 129130496 | 65.6 | true | true | true |
| 10 | 500 | 21294623 | 1291392.31 | 0.0 | 0.0 | 0.0 | 21294342 | 0 | 0 | 8 | 256 | 131072 | 124076032 | 84.5 | true | true | true |
| 10 | 1000 | 21465851 | 1307029.34 | 0.0 | 0.0 | 0.0 | 21465572 | 0 | 0 | 8 | 256 | 131072 | 141193216 | 85.1 | true | true | true |
| 30 | 1 | 318 | 10.59 | 94.0 | 97.1 | 105.4 | 0 | 0 | 0 | 1 | 0 | 16384 | 23240704 | 8.4 | true | true | true |
| 30 | 10 | 1254 | 41.54 | 210.7 | 390.2 | 480.7 | 0 | 0 | 0 | 8 | 2 | 131072 | 132374528 | 65.7 | true | true | true |
| 30 | 32 | 1290 | 42.01 | 732.0 | 2425.8 | 3085.7 | 0 | 0 | 0 | 8 | 24 | 131072 | 125693952 | 66.1 | true | true | true |
| 30 | 100 | 1346 | 41.65 | 2362.9 | 6746.0 | 8962.1 | 0 | 0 | 0 | 8 | 92 | 131072 | 128348160 | 65.9 | true | true | true |
| 30 | 250 | 1504 | 41.87 | 5933.8 | 17478.4 | 23292.8 | 0 | 0 | 0 | 8 | 242 | 131072 | 127442944 | 66.1 | true | true | true |
| 30 | 500 | 64766778 | 1778343.70 | 0.0 | 0.0 | 0.5 | 64766464 | 0 | 0 | 8 | 256 | 131072 | 120721408 | 90.7 | true | true | true |
| 30 | 1000 | 63927769 | 1750810.16 | 0.0 | 0.0 | 0.0 | 63927457 | 0 | 0 | 8 | 256 | 131072 | 137031680 | 91.2 | true | true | true |
| 60 | 1 | 649 | 10.80 | 91.9 | 96.7 | 101.5 | 0 | 0 | 0 | 1 | 0 | 16384 | 24186880 | 8.3 | true | true | true |
| 60 | 10 | 2508 | 41.62 | 216.0 | 368.6 | 446.0 | 0 | 0 | 0 | 8 | 2 | 131072 | 128794624 | 66.0 | true | true | true |
| 60 | 32 | 2526 | 41.58 | 749.4 | 1961.1 | 3174.6 | 0 | 0 | 0 | 8 | 24 | 131072 | 131653632 | 66.0 | true | true | true |
| 60 | 100 | 2601 | 41.73 | 2368.1 | 6823.0 | 11154.5 | 0 | 0 | 0 | 8 | 92 | 131072 | 125997056 | 65.9 | true | true | true |
| 60 | 250 | 2711 | 41.07 | 5983.0 | 17750.9 | 23614.9 | 0 | 0 | 0 | 8 | 242 | 131072 | 129531904 | 65.8 | true | true | true |
| 60 | 500 | 126455387 | 1904402.08 | 0.0 | 0.0 | 0.0 | 126455017 | 0 | 0 | 8 | 256 | 131072 | 125857792 | 93.6 | true | true | true |
| 60 | 1000 | 128445396 | 1924018.38 | 0.0 | 0.0 | 0.0 | 128445036 | 0 | 0 | 8 | 256 | 131072 | 142852096 | 92.9 | true | true | true |

## Malformed input

- 10s×32: ops=82894289 expected_err=82894289 unexpected=0 panics=0 idle=true
- 10s×100: ops=84962724 expected_err=84962724 unexpected=0 panics=0 idle=true
- 10s×250: ops=87275318 expected_err=87275318 unexpected=0 panics=0 idle=true
- 30s×32: ops=259324753 expected_err=259324753 unexpected=0 panics=0 idle=true
- 30s×100: ops=256143276 expected_err=256143276 unexpected=0 panics=0 idle=true
- 30s×250: ops=256449255 expected_err=256449255 unexpected=0 panics=0 idle=true

## Failure / permit release

- 10s×100: hashes=270 wrong_ok=242 rejects=0 unexpected=0 panics=0 idle=true
- 30s×250: hashes=781 wrong_ok=706 rejects=0 unexpected=0 panics=0 idle=true
- 10s×500: hashes=202 wrong_ok=72 rejects=22158215 unexpected=0 panics=0 idle=true

## Overload / queue_limit enforcement

- 10s×500: rejects=24155878 peak_q=256 peak_KiB=131072 q_ok=true idle=true — expects rejects when concurrency>256; rejects=24155878 peak_q=256 enforced=true
- 30s×1000: rejects=71516034 peak_q=256 peak_KiB=131072 q_ok=true idle=true — expects rejects when concurrency>256; rejects=71516034 peak_q=256 enforced=true

## Notes

- Workload uses production `hash` / `verify` and the process-wide `OnceLock` scheduler.
- `ResourceExhausted` under overload is counted as `rejected_resource`, not an unexplained error.
- Peak KDF allocation is sampled from `scheduler_stats().allocated_kib` and must stay ≤ 131072 KiB.
- No KDF algorithm, API, hash format, or ResourcePolicy defaults were changed for this campaign.
- Binding limit under default 16 MiB hashes and 128 MiB host ceiling is **8 concurrent admits** (`peak_active_permits=8`, `peak_allocated_kib=131072` on every multi-worker run).
- At concurrency **500 and 1000**, the admission queue saturates at `queue_limit=256` and most requests fail fast with `ResourceExhausted`. All-ops p50/p95/p99 therefore approach 0 ms (rejection latency). Sustained admitted throughput remains ~41–42 ops/s (see concurrency ≤250 rows).
- After every scenario the scheduler returned to idle: `active_jobs=0`, `waiting_jobs=0`, `allocated_kib=0`.

