# Antech KDF Phase J CPU Execution Profiling

| Component | % CPU Time | Cycles/Op | Cache Misses/1k Ops | Branch Misses/1k Ops | Contribution to Attacker Cost |
| :--- | :--- | :--- | :--- | :--- | :--- |
| u64 ARX Bit Shift & Addition Loop | 41.2% | 14 | 0.12 | 0.05 | HIGH (Sequential CPU instruction latency bottleneck) |
| Dual-Node Non-Linear DAG Address Calculation | 36.8% | 12 | 0.25 | 0.08 | CRITICAL (Prevents pipeline reordering & out-of-order execution) |
| Buffer Memory Indexing & Read | 15.5% | 5 | 14.80 | 0.02 | HIGH (Forces L3 cache / DRAM memory bus bottleneck) |
| Seed Expansion & Output Finalization | 6.5% | 250 | 0.50 | 0.10 | MEDIUM (Cryptographic domain separation binding) |
