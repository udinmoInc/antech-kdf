# Chapter 7: Future Research & Roadmap

To address the technical open questions identified in [Chapter 6: Limitations](06-limitations.md), future research will focus on five concrete engineering and cryptographic objectives.

### 1. Physical CUDA GPU Benchmark Execution
The immediate priority is establishing an automated GPU evaluation pipeline on a dedicated Linux build host equipped with the NVIDIA CUDA Compiler Toolkit (`nvcc`). We plan to compile raw `.cu` verification kernels and measure physical execution throughput ($g/s$), memory bus saturation, and warp execution divergence across high-end desktop GPUs (NVIDIA RTX 4090 / 3090) and enterprise data center accelerators (NVIDIA A100 / H100).

### 2. Formal Cryptanalysis & Security Audit
We intend to invite independent third-party cryptographers to perform rigorous formal cryptanalysis on Candidate-004. Key areas of investigation include evaluating Variant K1 dynamic S-box state feedback against differential attack vectors and analyzing Variant K2 Quad-DAG memory structures against advanced graph-pebbling algorithms.

### 3. ASIC & FPGA Hardware Cost Synthesis
To evaluate custom hardware resistance beyond standard CPU architectures, we plan to model ARX step logic on FPGA hardware synthesis toolchains (such as Xilinx Vivado). This analysis will estimate gate count, die area, and power consumption for dedicated ASIC cracking chips.

### 4. Cache-Timing Mitigation & Hybrid Mode Design
To address potential side-channel risks associated with data-dependent memory indexing, we will explore a hybrid execution mode. Similar to Argon2id's hybrid design, an initial pass could use data-independent memory filling to protect against cache-timing attacks, followed by data-dependent dependency passes to maintain high TMTO and GPU warp divergence resistance.

### 5. Multi-Architecture CPU & SIMD Vectorization Audit
We plan to expand CPU attacker benchmarking across diverse hardware platforms, including ARM64 (Apple Silicon M-series, AWS Graviton3) and RISC-V architectures. This will assess whether AVX-512 or ARM Neon SIMD vector extensions can achieve higher parallel cracking efficiency against Variant K1 and Variant K2.

For a summary of baseline results achieved so far, see [Chapter 5: Measured Results](05-results.md). For repository build instructions and dataset access, return to the main [Research Overview](README.md).
