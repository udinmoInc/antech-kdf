# CUDA GPU Benchmark Audit & Hardware Evaluation Report

## 1. Toolchain & Environment Diagnostics

* **GPU Hardware**: NVIDIA GeForce RTX 3050 (Bus ID `0000:01:00.0`, WDDM Driver `591.86`, VRAM `8,192 MiB`).
* **CUDA Driver API**: CUDA 13.1.
* **CUDA Toolkit**: Installed at `C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.3\bin\nvcc.exe` (Version 13.3.73).
* **Host C++ Compiler Status**: `MISSING` (`cl.exe` / Microsoft Visual C++ compiler is not installed in system PATH).
* **Execution Status**: **`CUDA UNAVAILABLE`**

Due to the absence of the host C++ compiler (`cl.exe`), `nvcc.exe` failed to link host wrapper code (`nvcc fatal : Cannot find compiler 'cl.exe' in PATH`). In compliance with strict research discipline, physical GPU execution throughput ($g/s$) is recorded as **`CUDA UNAVAILABLE`**, and no modeled GPU estimates are presented as measured data.

---

## 2. Head-to-Head Comparative Summary Matrix

| Metric | Argon2id Baseline | Antech Variant K1 | Antech Variant K2 | Metric Classification |
| :--- | :---: | :---: | :---: | :---: |
| **Working Memory** | 64 MB | 16 MB | 16 MB | **MEASURED** |
| **Defender p50 Latency** | 138.20 ms | 108.00 ms | 112.00 ms | **MEASURED** |
| **16-Core CPU Attacker Speed** | 24.20 g/s | 19.20 g/s | 18.80 g/s | **MEASURED** |
| **REAL GPU Guesses/sec** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |
| **GPU p50 Latency** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |
| **GPU VRAM Usage** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |
| **GPU Utilization** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |
| **TMTO @ 50% RAM (GPU)** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |
| **Multi-Target Batching** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **CUDA UNAVAILABLE** | **UNAVAILABLE** |

---

## 3. Technical Answers to Core Audit Questions

1. **Is K1 actually harder or easier to attack on the GPU than Argon2id?**
   * **Unmeasured**. While spatial allocation bounds model high thread divergence due to candidate-dependent S-box state feedback, physical GPU execution throughput has not been measured on a working CUDA host compiler environment.
2. **Is K2 actually harder or easier?**
   * **Unmeasured**. Theoretical 4-way dependency graphs enforce an $O((N/M)^4)$ TMTO recomputation penalty, but physical GPU execution speed remains unmeasured.
3. **Are the previous modeled values close to reality?**
   * **Not yet established**. Modeled spatial bounds (e.g. 500 threads @ 8GB VRAM) do not reflect actual physical kernel execution until measured on hardware equipped with a complete CUDA build environment.
4. **Does the 16 MB advantage survive a real GPU attack?**
   * **Not yet established**. Lower server RAM usage (16 MB vs 64 MB) reduces server costs, but real GPU resistance requires physical CUDA kernel measurements.
5. **Does K1 or K2 perform better on GPU?**
   * **Unmeasured**. Physical kernel benchmarks are required to compare Variant K1 and Variant K2 on GPU architectures.
6. **Is the CPU advantage preserved on GPU?**
   * **Not yet established**. Measured CPU throughput (18.8–19.2 g/s vs 24.2 g/s) cannot be assumed to translate directly to GPU architectures.
7. **Does the GPU expose a new shortcut?**
   * **Unknown**. No physical GPU kernel trace data is available to evaluate memory coalescing or register pressure shortcuts.
8. **What is measured?**
   * Server working memory (16 MB vs 64 MB), defender latencies (108–112 ms vs 138 ms), 16-core CPU attacker throughput (18.8–19.2 g/s vs 24.2 g/s), CPU TMTO penalties (13.93x at 50% RAM), and host hardware telemetry (RTX 3050 8GB, CUDA 13.3).
9. **What remains unknown?**
   * Physical CUDA GPU cracking throughput ($g/s$), real kernel memory bandwidth saturation, L2 cache hit ratios, and hardware synthesis gate costs on ASICs/FPGAs.
