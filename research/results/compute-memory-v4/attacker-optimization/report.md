# Antech v4-C attacker optimization

Attacker-only work. Production `hash()` / `verify()` / `needs_rehash()` and v4-C graph mix were not changed. Defender parameters stay 16 MiB CombinedFrontier.

## Summary table

| Attacker | Baseline g/s | Optimized g/s | Improvement |
|---|---:|---:|---:|
| CPU 16T | 39.808 | 43.101 | 1.083× |
| CPU 32T | 34.137 | 44.409 | 1.301× |
| RTX 3050 GPU | 15.431 | 74.940 | 4.856× |

Best CPU packed strategy at 16 threads: `packed_prefetch`.

## vs Argon2id (same machine, corpus, salt, 1.2 s window, warmup)

| | Antech opt | Argon2id |
|---|---:|---:|
| CPU 16T g/s | 43.101 | 23.038 |
| CPU 32T g/s | 44.409 | 25.342 |
| GPU g/s | 74.940 | 435.556 |

## What limits the attacker

Each guess is a 524288-node CombinedFrontier walk. Parent indices are **state-dependent**, so the DAG cannot be precomputed and independent nodes cannot be reordered inside a guess. Dual far-scatter XOR updates earlier blocks, so a full 16 MiB resident buffer is required for an exact digest (no lossless skip of nodes).

Local parents hit the last 64 blocks; far gathers and scatters are random in `[0, i-64)`. That random traffic dominates. Skipping the frontier ring is valid and often faster (one less 32-byte copy per node).

GPU: one thread owns one 16 MiB walk. Neighboring threads do not share block indices, so global loads do not coalesce. Occupancy is VRAM-bound (~16 MiB × batch). This is mostly **intrinsic to the graph**, not only a kernel bug — kernel packing (u64 words, skip memset) still helps the inner loop.

## Attacker-side reductions tried

| Idea | Result |
|---|---|
| Reuse scratch across guesses | Kept (allocation eliminated). |
| Compress blocks | 32-byte mixed state does not compress usefully. |
| Precompute graph metadata | Impossible: addresses depend on running state. |
| Reorder independent work | No independent nodes inside a guess. |
| Batch passwords | CPU dual lock-step; GPU batch. |
| Skip ring / skip memset | Valid; measured. |
| Avoid materializing nodes | Invalid for exact digest (scatters + far reads). |

## CPU scaling (all strategies)

| Impl | 1T | 8T | 16T | 32T | 16T eff |
|---|---:|---:|---:|---:|---:|
| production_engine | 7.81 | 31.69 | 39.81 | 34.14 | 0.318 |
| packed_ring | 8.73 | 33.45 | 42.90 | 41.95 | 0.307 |
| packed_noring | 6.18 | 34.07 | 42.46 | 42.48 | 0.429 |
| packed_prefetch | 8.79 | 34.32 | 43.10 | 44.41 | 0.306 |
| packed_dual_lockstep | 7.12 | 31.08 | 32.48 | 39.68 | 0.285 |
| argon2id | 9.82 | 23.27 | 23.04 | 25.34 | 0.147 |

## GPU notes

CUDA binary compiled; ptxas log in `ptxas.txt`.

```
**********************************************************************
** Visual Studio 2022 Developer Command Prompt v17.0
** Copyright (c) 2025 Microsoft Corporation
**********************************************************************
[vcvarsall.bat] Environment initialized for: 'x64'
ptxas info    : 0 bytes gmem
ptxas info    : Compiling entry function '_Z31v4c_guess_kernel_packed_persistPKhS0_PyS1_Phii' for 'sm_86'
ptxas info    : Function properties for _Z31v4c_guess_kernel_packed_persistPKhS0_PyS1_Phii
    432 bytes stack frame, 0 bytes spill stores, 0 bytes spill loads
ptxas info    : Used 60 registers, used 0 barriers, 432 bytes cumulative stack size, 400 bytes cmem[0], 24 bytes cmem[2]
ptxas info    : Compile time = 0.000 ms
ptxas info    : Compiling entry function '_Z23v4c_guess_kernel_packedPKhS0_PyS1_Phii' for 'sm_86'
ptxas info    : Function properties for _Z23v4c_guess_kernel_packedPKhS0_PyS1_Phii
    2480 bytes stack frame, 0 bytes spill stores, 0 bytes spill loads
ptxas info    : Used 60 registers, used 0 barriers, 2480 bytes cumulative stack size, 400 bytes cmem[0], 24 bytes cmem[2]
ptxas info    : Compile time = 0.000 ms
ptxas info    : Compiling entry function '_Z27v4c_guess_kernel_fused_zeroPKhS0_PhPyS1_i' for 'sm_86'
ptxas info    : Function properties for _Z27v4c_guess_kernel_fused_zeroPKhS0_PhPyS1_i
    2304 bytes stack frame, 0 bytes spill stores, 0 bytes spill loads
ptxas info    : Used 72 registers, used 0 barriers, 2304 bytes cumulative stack size, 396 bytes cmem[0], 24 bytes cmem[2]
ptxas info    : Compile time = 0.000 ms
ptxas info    : Compiling entry function '_Z16v4c_guess_kernelPKhS0_PhPyS1_i' for 'sm_86'
ptxas info    : Function properties for _Z16v4c_guess_kernelPKhS0_PhPyS1_i
    2304 bytes stack frame, 0 bytes spill stores, 0 bytes spill loads
ptxas info    : Used 72 registers, used 0 barriers, 2304 bytes cumulative stack size, 396 bytes cmem[0], 24 bytes cmem[2]
ptxas info    : Compile time = 0.000 ms
v4c_gpu_attacker.cu
tmpxft_00003f8c_00000000-7_v4c_gpu_attacker.cudafe1.cpp


```

L2 hit rate / SM util from Nsight are recorded as UNAVAILABLE unless nsys/ncu produced counters.

## Answers

1. CPU improvement vs this run's production 16T/32T: 1.083× / 1.301×.

2. GPU improvement vs this run's baseline kernel: 4.856×.

3. Limit: data-dependent far gathers/scatters over 16 MiB, 524288 serial mix steps.

4. ~33 g/s was partly kernel (byte loads, memset, occupancy) and partly intrinsic uncoalesced 16 MiB walks. See GPU table.

5. No digest-preserving shortcut: parent indices are not reusable across passwords; TMTO that drops blocks changes the digest or multiplies compute.

6. Packed attacker parallel efficiency: 16T 0.306, 32T 0.158 (vs 1T).

7. GPU still cannot merge walks across the warp; packing helps arithmetic, not coalescing.


Hardware counters (instructions/IPC/cache misses) require Linux `perf` or Nsight; on this Windows host they are marked UNAVAILABLE unless those tools ran. Cycles/guess use `RDTSC` around each guess.

