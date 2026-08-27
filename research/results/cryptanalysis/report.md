# Cryptanalysis report — canonical Antech KDF

Target: production `AntechEngine` / CombinedFrontier / 16 MiB default.

## Full evaluation baseline (16 MiB)

- nodes (num_blocks): **524288**
- mix_pairs: **1572349**
- parent_gathers: **3144642**
- scatters: **1048446**
- unique parents touched: **524287**
- far vs frontier hits: **2094786** / **1049856**
- 1-thread throughput: **1.43 guesses/s** (697.1 ms/guess)

## Answers to required questions

1. **Can the DAG be reduced?** No for a correct digest. Gather-reachability from the last node leaves some nodes unused *as parents*, but the rolling 256-bit state is updated on every node and feeds parent selection + finalize — skipping any node changes the digest (A1).

2. **Can the attacker skip nodes?** Prototype skip-every-other-node: **INCORRECT**. No correct skip schedule found.

3. **Can predecessor selection be predicted?** Exact local+remote parent-set match from only `state[0]` (pre-node, no local mix) is ≈0.00% of nodes (A3). Far parents need post-local full state; not enough to skip the walk.

4. **Can state size be reduced?** Algebraic probes show mix_pair is **not** XOR-linear; zero inputs are not identity. No smaller state representation found that preserves outputs.

5. **Can computations be shared?** Within one guess: phantoms are trivial; nodes produce unique blocks. Across guesses: seed binds password — **no** shared DAG work (A6/A10).

6. **More efficient parallelization than current attacker?** Intra-DAG parallelism is blocked by the sequential state. Cross-guess parallelism scales with threads/GPU. Packed+prefetch improves constants but does not reduce mix count (A8).

7. **Memory reduction without recomputation penalty?** **No.** Naive checkpoint TMTO is **INCORRECT** on CombinedFrontier because dual scatter mutates past blocks; eviction without a complete scatter replay breaks digests (A4a). Scatter-log TMTO prototypes also failed correctness in this campaign (A4b). No correct sub-full-memory attack beat full evaluation.

8. **Algebraic shortcut in state transition?** Not found (A2).

9. **Strongest cheaper correct attack:** `A8_packed_prefetch_full_eval` — Full DAG with packed u64 layout + prefetch (no node skip)

10. **How much cheaper?** attack_work/full_work ≈ **0.709** (70.9% of reference defender latency). Measured 8.79 vs baseline 6.23 guesses/s at 1 thread / 16 MiB.

> **Important:** This reduces wall-clock via layout/prefetch only. Node count and mix_pair count are unchanged — it is **not** a mathematical shortcut past the DAG.

## CPU scaling (strongest schedule attack)

| Attack | Threads | GPS | work_ratio vs full@1t |
|---|---|---|---|
| full_eval | 1 | 7.64 | 0.964 |
| packed_prefetch | 1 | 7.90 | 0.932 |
| full_eval | 16 | 36.97 | 3.187 |
| packed_prefetch | 16 | 34.29 | 3.436 |
| full_eval | 32 | 28.76 | 8.195 |
| packed_prefetch | 32 | 34.67 | 6.798 |

## GPU

- mode=none gps=0.00 status=UNAVAILABLE — No CUDA binary or prior GPU CSV

## Important caveat

Absence of a found shortcut is **not** a security proof. This campaign shows that several natural reduction strategies fail or lose on the work metric against the current production construction.

