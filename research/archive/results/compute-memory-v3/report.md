# Compute-memory v3 results

v2 scaled too well for multi-core attackers: each guess is independent, and at 16 MiB many working sets fit concurrently. v3 keeps work = `memory / block_size` and changes parent shape.

| Threads | A cut | B recursive | C frontier | Argon2id |
|---:|---:|---:|---:|---:|
| 1 | 9.14 | 4.70 | 3.82 | 10.69 |
| 8 | 50.29 | 24.26 | 22.31 | 23.06 |
| 16 | 56.65 | 32.31 | 25.15 | 24.52 |
| 32 | 48.07 | 27.15 | 24.00 | 22.69 |

Defender p50 @ 16 MiB: A 116.6 ms, B 222.7 ms, C 247.3 ms. vs v2 (~76 g/s @16t / ~69 @32t), C cuts multi-core attacker throughput by ~3× and sits near Argon2id’s plateau.

Parents: A epoch cut + far edges; B power-of-two intervals; C recent frontier + remote gather/scatter. TMTO @50%: A/C ~5.2×, B ~3.8× (C’s sparse TMTO path can disagree with full-memory digests when scatter writebacks are skipped). Research focus after this pass was narrow-frontier, then v4 combined-frontier.
