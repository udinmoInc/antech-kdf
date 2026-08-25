# Review Questions — Antech KDF

Please **hunt for attacks**, not confirmations. A useful review finds a cheaper correct evaluation, a broken binding, or a clear negative result with a reproduction.

For each idea: state assumptions, memory, work relative to full evaluation, and whether digests match [`test-vectors.json`](./test-vectors.json) / production `AntechEngine`.

## Graph and dependencies

1. Can the CombinedFrontier DAG be **reduced** (skip nodes) while matching the digest?
2. Can **parent indices** be predicted from partial state?
3. Can **far parents** or dual **scatter destinations** be anticipated cheaply?
4. Is there a **topological shortcut**, condensation, or cut that removes work?

## State and algebra

5. Can the 256-bit ARX state be **reduced**, factored, or linearized?
6. Does `MixPair` admit **algebraic simplification**, fixed points, or weak rounds?
7. Are there **state collisions** or multi-collisions that aid guessing?
8. Can the computation be **reversed** from the final state / last block?

## Memory and TMTO

9. Is there a correct **time–memory tradeoff** below 16 MiB with acceptable cost?
10. Do **checkpoints / pebbling schedules** beat full memory?
11. Can **scatter state** be compressed, delta-encoded, or deferred correctly?
12. Does **frontier-only** storage suffice?

## Parallelism and hardware

13. Can **intra-DAG** work be parallelized beyond the sequential state chain?
14. What is the best **multi-guess CPU** scaling?
15. What is the best **GPU** strategy (occupancy, VRAM per guess, batching)?
16. Are there **FPGA/ASIC** shortcuts (smaller datapath, fused mix, memory hierarchy)?

## Multi-target and precomputation

17. Is there **cross-password** or **cross-salt** shared work?
18. Does **common-subexpression** reuse exist inside one evaluation?
19. Can **rainbow / Hellman** tables help under this seed binding?

## Binding and parameters

20. Is **password/salt/config binding** in `BindSeed` sound (length fields, domain separation)?
21. Can **parameter manipulation** in encoded hashes weaken verification?
22. Is there an **early-reject** path that leaks whether a prefix is correct?

## Side channels (secondary)

23. Does the reference/production path leak via **timing**, cache, or memory access patterns tied to secrets beyond the public salt?

## Output

24. Are **digest collisions** or length-extension style issues relevant given SHA-256 wrapping?

Deliver findings as: attack idea → reduced work/memory → correctness evidence → reproduction.
