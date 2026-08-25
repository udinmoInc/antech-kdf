# Cryptanalysis report — canonical Antech KDF

**Date:** 2026-08-25  
**Target:** production `AntechEngine`, graph=`CombinedFrontier`, default **16 MiB**, block=32, fan-in=2  
**Constraint:** attacker-only; KDF / defender unchanged  

**Primary metric:** `attack_work / full_work` ≈ `baseline_gps / attack_gps` for correct digests (lower is cheaper).

---

## Full evaluation baseline (16 MiB)

| Metric | Value |
|---|---|
| num_blocks | **524288** |
| mix_pairs | **1171055** |
| parent_gathers | **1954966** |
| scatters | **1048446** |
| unique parents touched | **524287** (~all prior blocks) |
| far / frontier parent hits | **715097** / **1239869** |
| 1-thread throughput | **9.64 guesses/s** (103.7 ms/guess) |

Baselines at 12/24/32 MiB are in `baseline-cost.csv` (latency scales roughly with memory).

---

## Answers to required questions

1. **Can the DAG be reduced?**  
   **No for a correct digest.** On the 1 MiB probe, gather+scatter BFS from the last node reached **100% of nodes**. Independently, every node updates the rolling 256-bit state used for parent selection and finalize — skipping any node changes the digest (A1).

2. **Can the attacker skip nodes?**  
   Prototype skip-every-other-node: **INCORRECT**. No correct skip schedule found.

3. **Can predecessor selection be predicted?**  
   Partial-state prediction (only `state[0]`): **~0.01%** exact parent-set matches (A3). Far parents and dual scatter need the full state.

4. **Can state size be reduced?**  
   **No.** `mix_pair` is not XOR-linear; zero inputs are not identity; 256 sample outputs had 0 collisions. No smaller state found that preserves digests (A2 / `state-reduction.csv`).

5. **Can computations be shared?**  
   **No meaningful cross-guess reuse.** Seed binds password+salt; parent indices bind rolling state; nodes write unique blocks (A6/A10).

6. **More efficient parallelization than the current attacker?**  
   **Intra-DAG:** blocked by sequential state. **Cross-guess:** scales with threads/GPU. Packed+prefetch improves constants only (A8) — same mix count.

7. **Memory reduction without recomputation penalty?**  
   **No.** Naive checkpoint TMTO is **INCORRECT** under dual scatter (past blocks are mutated; eviction without complete scatter replay breaks digests — A4a). Scatter-log TMTO prototypes also failed correctness here (A4b). No correct sub-full-memory attack beat full evaluation.

8. **Algebraic shortcut in the state transition?**  
   **Not found** (A2).

9. **Strongest cheaper correct attack:**  
   `A8_packed_prefetch_full_eval` — full DAG, packed `u64` layout + prefetch (no node skip).

10. **How much cheaper?**  
    `attack_work/full_work` ≈ **0.512** (≈**48.8%** wall-clock savings vs the reference byte-buffer `AntechEngine` walk at 1 thread / 16 MiB).  
    Measured **18.35** vs **9.40** guesses/s.

> This is an **implementation/schedule** advantage only. Cryptographic work (node count / `mix_pair` count) is **unchanged** — not a mathematical DAG shortcut.

---

## CPU scaling (full eval vs strongest schedule attack)

| Attack | Threads | GPS | work_ratio vs full@1t |
|---|---|---|---|
| full_eval | 1 | 9.44 | 0.978 |
| packed_prefetch | 1 | 17.97 | 0.514 |
| full_eval | 16 | 41.99 | 3.517 |
| packed_prefetch | 16 | 68.34 | 2.161 |
| full_eval | 32 | 38.93 | 7.588 |
| packed_prefetch | 32 | 63.37 | 4.661 |

At 32 threads, packed_prefetch ≈ **63.4 g/s** (still full DAG per guess). Throughput drops slightly vs 16 threads (memory bandwidth / contention).

---

## GPU (RTX 3050-class)

| Mode | GPS | Status |
|---|---|---|
| packed_t32_b256 (prior verified campaign) | **100.53** | PRIOR_CORRECT (100/100 digests) |

Still a **full-node** walk per guess; batching across guesses. ≈**10.4×** vs 1-thread full_eval (9.64 g/s) — not reduced per-guess DAG work.

---

## Attack outcome summary

| ID | Result | work_ratio | Notes |
|---|---|---|---|
| A1 skip nodes | INCORRECT | — | State chain + full gather reachability |
| A2 algebraic | FAIL (no shortcut) | 1.0 | ARX not linear |
| A3 parent predict | FAIL | 1.0 | ~0.01% partial-state matches |
| A4a naive TMTO | INCORRECT | — | Dual scatter breaks eviction |
| A4b scatter-log TMTO | INCORRECT | — | Prototype did not match digests |
| A5 MITM split | CORRECT, no savings | 1.0 | Halves not independent |
| A6 precompute | none | 1.0 | Seed binds password |
| A7 frontier-only | needs recompute | — | Far gathers + scatter |
| **A8 packed prefetch** | **CORRECT, cheaper wall-clock** | **0.512** | Schedule only |
| A9 dual walk | CORRECT | 1.0/guess | 2× memory |
| A10 CSE | none | 1.0 | Unique per-node blocks |

---

## Artifacts

| File | Contents |
|---|---|
| `attack-catalog.md` | All attempted attacks |
| `baseline-cost.csv` | Full-eval cost 12–32 MiB |
| `graph-reduction.csv` | Influence / skip analysis |
| `state-reduction.csv` | Algebraic + parent prediction |
| `parallelization.csv` | Intra- vs cross-guess parallelism |
| `tmto-shortcuts.csv` | TMTO correctness results |
| `precomputation.csv` | Cross-guess reuse analysis |
| `multitarget.csv` | Multi-hash reuse |
| `cpu-results.csv` | 1/16/32 thread measurements |
| `gpu-results.csv` | GPU throughput |

Harness: `research/code/antech-kdf-research/src/cryptanalysis/` + `examples/cryptanalysis_runner.rs`.

---

## Caveat

**Absence of a found mathematical shortcut is not a security proof.** This campaign shows that several natural reduction strategies fail or do not reduce cryptographic work against the current production CombinedFrontier construction. The only measured “cheaper” correct attack is constant-factor scheduling (packed layout / prefetch / GPU batching) with **unchanged** node/mix counts.
