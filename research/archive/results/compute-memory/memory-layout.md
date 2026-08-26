# Memory layout (compute-memory)

Dominant cost is the block buffer: `num_blocks × block_size` with `num_blocks = memory_bytes / block_size`. At the default 16 MiB / 32 B that is 524 288 nodes.

Extra heap beside the buffer is small (seed digest, scratch, frontier ring for combined-frontier, alignment). The 256-bit mix state lives in registers. There is no separate depth/passes buffer in the production engine.

| Memory | Blocks (32 B) |
|---:|---:|
| 1 MiB | 32 768 |
| 4 MiB | 131 072 |
| 12 MiB | 393 216 |
| 16 MiB | 524 288 |
| 24 MiB | 786 432 |
| 32 MiB | 1 048 576 |

Small footprints (1–4 MiB) fit in many L3 caches and are weak as capacity-hard targets. 16 MiB and up are the profiles used in the main campaigns.
