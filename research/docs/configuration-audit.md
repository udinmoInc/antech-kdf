# Configuration notes

How fixed values are treated in this repo:

| Kind | Examples |
|---|---|
| Protocol constants | Domain separators (`antech-compute-memory-v4-seed`, …), ARX shift schedule, `$antech$` / `v2` tags, graph tags |
| Safety limits | Memory 1–1024 MiB, salt 8–256 B, block size 16–64 B, output length bounds in `antech-kdf-types` |
| Defaults | 16 MiB memory, 16 B salt, fan-in 2, combined-frontier, 128 MiB / 64 jobs / queue 256 resource policy |
| Research-only | Attacker thread grids, CUDA batch sizes, historical archived engines |

Do not change protocol constants without treating it as a breaking crypto change. Defaults and research knobs are free to tune behind builders and runners.

Normative defaults: [`../security-review/specification.md`](../security-review/specification.md) and `AntechConfig::default()`.
