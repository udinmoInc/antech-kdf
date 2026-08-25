# Architecture

```text
PRODUCTION
antech-kdf            hash / verify / needs_rehash
    │
antech-kdf-core       AntechEngine, BoundedResourceScheduler
    │
antech-kdf-format     v2 encode / parse
antech-kdf-types      AntechConfig, GraphKind, errors, RehashPolicy

RESEARCH (separate workspace under research/code/)
antech-kdf-research → antech-kdf / antech-kdf-core
antech-kdf-reference → (readable mirror; tests vs core)
```

| Crate | Role |
|---|---|
| `antech-kdf` | Developer API |
| `antech-kdf-core` | Canonical engine |
| `antech-kdf-format` | `$antech$v2$...` strings |
| `antech-kdf-types` | Shared types |
| `antech-kdf-cli` | CLI |
| `antech-kdf-ffi` | C ABI |

Research crates are **not** members of the root workspace. They live under [`research/code/`](../research/code/).

There is one production engine: `AntechEngine`. Structural knobs are memory, block size, fan-in, graph kind, salt length, and output length. Defaults use the combined-frontier graph.

`AntechConfig` sets per-operation memory. `BoundedResourceScheduler` enforces a separate host ceiling (default 128 MiB across concurrent jobs). The two layers do not substitute for each other.
