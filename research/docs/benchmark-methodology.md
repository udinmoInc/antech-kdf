# Benchmark methodology

Record CPU model, core/thread counts, RAM, OS, compiler, GPU, and driver for every campaign. Keep that next to the results (`hardware.json`, or a short note in the campaign report).

Warm up a few untimed iterations, then report p50 / p95 / p99 (or median kernel time for GPU). Attacker throughput is guesses per second against real salts, not synthetic stubs.

Label every number:

- `MEASURED` — ran on stated hardware
- `MODELED` — spatial or analytic bound only
- `BLOCKED` — tool or environment prevented the run
- `UNKNOWN` / `UNAVAILABLE` — not run

Baselines (Argon2id, …) stay on their stated parameters; do not retune them mid-comparison. Release builds, same flags, same host class when claiming a head-to-head.

**Current canonical datasets** for public tables:

- CPU / TMTO: `research/results/compute-memory-v4/`
- GPU head-to-head: `research/results/compute-memory-v4/gpu/`
- Cryptanalysis: `research/results/cryptanalysis/`

Do not mix those campaigns into one composite “best rate.”
