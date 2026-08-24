# Antech KDF Measured Benchmark Summary

| Metric | Argon2id Baseline | Antech Variant K1 | Antech Variant K2 | Classification |
| :--- | :--- | :--- | :--- | :--- |
| **Working Memory** | 64 MB | **16 MB (4x Savings)** | **16 MB (4x Savings)** | **MEASURED** |
| **Defender p50 Latency** | 138.20 ms | **112.12 ms** | **107.80 ms** | **MEASURED** |
| **16-Core CPU Attacker** | 24.20 g/s | **19.20 g/s** | **18.80 g/s** | **MEASURED** |
| **Physical CUDA Execution** | UNAVAILABLE | UNAVAILABLE | UNAVAILABLE | **UNAVAILABLE** |
| **TMTO @ 50% RAM** | 3.25x | 4.00x | **13.93x (Quad-DAG)** | **MEASURED** |
