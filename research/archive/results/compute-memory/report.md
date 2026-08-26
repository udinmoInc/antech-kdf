# Compute-memory v2 results

Work is one pass over `memory_bytes / block_size` nodes (fan-in fixed). No depth/pass security knob.

| Metric | Argon2id | Candidate-004 | Compute-memory v2 |
|---|---:|---:|---:|
| Memory | 64 MiB | 16 MiB | 16 MiB |
| Defender p50 | 99.78 ms | 28.04 ms | 85.70 ms |
| Work bound | Argon2 lanes×blocks | depth=120 loop | 524288 nodes |
| CPU attacker (1t) | — | — | 10.11 g/s |
| GPU | — | — | UNAVAILABLE (no host `cl.exe` at the time) |
| TMTO @ 50% | — | — | 10.12× |

Seed binds password, salt, version, memory, block size, fan-in. Parents are `i-1` plus state-dependent earlier nodes. Research-only; public API unchanged.
