# Chapter 6: Known Research Limitations

Evaluating a experimental key derivation function requires transparent recognition of technical and methodological boundaries. While the empirical results presented in [Chapter 4: Evaluation](04-evaluation.md) demonstrate favorable CPU performance at 16 MB RAM, several significant limitations remain.

### Pending Real CUDA GPU Measurement
The primary technical limitation of this study is the absence of physical CUDA GPU benchmark execution. Because host build environments lacked the NVIDIA CUDA Compiler Toolkit (`nvcc.exe`), GPU parallelism and warp divergence metrics were evaluated using spatial allocation modeling rather than direct physical measurements. Spatial models confirm that a 16 MB allocation limits an 8 GB VRAM GPU to 500 parallel threads (**MODELED**), but direct execution throughput ($g/s$) on physical NVIDIA or AMD hardware remains **`UNAVAILABLE`**. Modeled spatial bounds must not be confused with measured physical cracking throughput.

### Unaudited ASIC & FPGA Custom Hardware Performance
While Variant K1 dynamic S-box feedback and Variant K2 Quad-DAG memory structures effectively slow down general-purpose x86 CPU attackers, custom hardware behavior remains unmeasured. Dedicated ASIC chips or high-end FPGAs with custom high-bandwidth memory (HBM) controllers might implement specialized pipeline architectures that mitigate ARX rotation divergence or multi-node memory fetch stalls.

### Cache-Timing & Shared Hardware Vulnerabilities
As noted in [Chapter 5: Security](05-security.md), Candidate-004 utilizes state-dependent memory addressing to maximize TMTO recomputation penalties. In multi-tenant cloud environments where malicious co-located processes monitor shared L3 cache lines, data-dependent memory accesses could theoretically leak cache-timing side-channel information.

### Absence of Independent Cryptanalysis
The construction evaluated in this project is an active research candidate and has not undergone third-party peer review or formal security reductions. Lowering working RAM from 64 MB to 16 MB inherently reduces total memory bandwidth resistance per hash. Lower measured CPU throughput on a specific host does not automatically prove equivalent overall cryptographic security under all attack models.

Finally, concurrency management using `ResourceController` solves systems-level OOM crash behavior; it does not enhance algorithmic security guarantees.

For planned methodologies to address these limitations, see [Chapter 7: Future Work](07-future-work.md).
