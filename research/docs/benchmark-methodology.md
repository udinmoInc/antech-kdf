# Benchmark methodology

Record CPU model, core/thread counts, RAM, OS, compiler, GPU, and driver for every campaign. Keep that in [data/hardware.md](data/hardware.md) or a results-side `hardware.json`.

Warm up a few untimed iterations, then report p50 / p95 / p99 (or median kernel time for GPU). Attacker throughput is guesses per second against real salts, not synthetic stubs.

Label every number:

- `MEASURED` — ran on hardware
- `MODELED` — spatial or analytic bound only
- `UNAVAILABLE` — not run

Baselines (Argon2id, scrypt, …) stay on their stated parameters; do not retune them mid-comparison. Release builds, same flags, same host class when claiming a head-to-head.
