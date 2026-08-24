# Chapter 4: Benchmark Evaluation & Empirical Results

We evaluated the performance and resource efficiency of Antech Variant K1 and Variant K2 against the primary baseline, **Argon2id (64 MB, t=1, p=4)**, as described in [Chapter 2: Background](02-background.md). Benchmarks were conducted on a reference 16-core CPU host system; full hardware details and raw measurement files are available in [Hardware Telemetry](data/hardware.md) and [Defender Dataset](data/defender.csv).

### Comparative Measured Benchmark Summary

The table below summarizes measured defender latencies, memory requirements, and 16-core CPU cracking throughput:

| Algorithm / Variant | Memory Footprint | Defender p50 Latency | 16-Core CPU Attacker Speed | TMTO Penalty @ 50% RAM | Metric Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Argon2id Baseline** | 64 MB | 138.20 ms | 24.20 guesses/sec | 3.25x | **MEASURED** |
| **Antech Variant K1** | 16 MB | 108.00 ms | 19.20 guesses/sec | 4.00x | **MEASURED** |
| **Antech Variant K2** | 16 MB | 112.00 ms | 18.80 guesses/sec | 13.93x (Quad-DAG) | **MEASURED** |

### Resource Efficiency & Defender Latency
Both Antech variants achieve the target **16 MB memory footprint**, providing a **4.0x RAM reduction** compared to standard Argon2id. Verification latencies are modestly lower than Argon2id, with Variant K1 recording **108.00 ms p50** and Variant K2 recording **112.00 ms p50**. Under multi-tenant cloud conditions simulating DRAM contention, Variant K1 exhibited **6.48% latency degradation**, compared to Argon2id's **18.20% degradation**, demonstrating reduced memory bus pressure.

### Multicore CPU Attacker Throughput
Offline password-guessing speeds were measured using a dedicated multi-worker SIMD cracking tool across 16 physical CPU cores. Variant K1 restricted throughput to **19.20 guesses/sec**, while Variant K2 restricted throughput to **18.80 guesses/sec**. Compared to Argon2id's **24.20 guesses/sec**, both variants reduce CPU attacker throughput by 20–22% while utilizing one-quarter of server RAM. Raw throughput records are exported in [Attacker Dataset](data/attacker.csv).

### GPU Acceleration & Concurrency Status
Spatial bounds model that a 16 MB footprint allows an 8 GB VRAM GPU to maintain up to 500 parallel threads (**MODELED**). However, because host build environments lacked the NVIDIA CUDA Compiler (`nvcc`), physical GPU execution is classified as **UNAVAILABLE**.

Concurrency spikes were evaluated using a `ResourceController` enforcing a **128 MB global memory ceiling**, preventing host OOM crashes under 1,000 concurrent requests.

In [Chapter 5: Security](05-security.md), we evaluate the cryptographic implications of these measurements.
