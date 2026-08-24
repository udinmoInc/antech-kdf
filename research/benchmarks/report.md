# Antech KDF Research Benchmark Summary

| Metric | Argon2id Baseline | Antech Variant K1 | Antech Variant K2 |
| :--- | :--- | :--- | :--- |
| **RAM** | 64 MB | **16 MB (4x Reduction)** | **16 MB (4x Reduction)** |
| **Defender p50 Latency** | 138.20 ms | **110.53 ms** | **108.07 ms** |
| **16-Core CPU Attacker** | 24.2 g/s | **19.2 g/s (Target Achieved)** | **18.8 g/s (Target Achieved)** |
| **TMTO @ 50% RAM** | 3.25x | 4.00x | **13.93x (Quad-DAG Penalty)** |
