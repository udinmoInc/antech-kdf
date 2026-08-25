# Antech KDF — Memory Layout Analysis

This document explains exactly where every byte goes for each memory target.
There are no unexplained allocations.

## Memory Formula

```
working_memory =
    blocks           (num_blocks × block_size)
  + seed             (32 bytes, SHA-256 password+salt derivation)
  + metadata         (12 bytes: memory_kib u32 + depth u32 + passes u32)
  + temp_workspace   (32 bytes, SHA-256 scratch per block fill)
  + alignment        (0–63 bytes, 64-byte cache-line rounding)

Note: state (4 × u64 = 32 bytes) lives in CPU registers, not heap.
```

## Why This Memory Size?

The buffer is filled with SHA-256 hashes of each block index before the main
dependency loop runs. This makes the initial buffer content non-trivially
compressible — an attacker cannot regenerate arbitrary blocks cheaply.
The dependency loop then reads and writes blocks based on current state,
so all `num_blocks` blocks must remain available in RAM throughout execution.

## Per-Target Breakdown

| Target | Blocks | Block Size | Num Blocks | State | Seed | Metadata | Temp | Align | Total Heap | Security Property |
|--------|--------|------------|------------|-------|------|----------|------|-------|------------|-------------------|
| 1.0 MiB | 1.0 MiB | 32 B | 32768 | 32 B | 32 B | 12 B | 32 B | 52 B | 1.0 MiB | Fits in L3 cache — GPU SIMD trivially parallelizable; no meaningful memory hardness |
| 2.0 MiB | 2.0 MiB | 32 B | 65536 | 32 B | 32 B | 12 B | 32 B | 52 B | 2.0 MiB | May exceed L3 on some GPUs; modest cache pressure; dependency still primary cost |
| 4.0 MiB | 4.0 MiB | 32 B | 131072 | 32 B | 32 B | 12 B | 32 B | 52 B | 4.0 MiB | May exceed L3 on some GPUs; modest cache pressure; dependency still primary cost |
| 12.0 MiB | 12.0 MiB | 32 B | 393216 | 32 B | 32 B | 12 B | 32 B | 52 B | 12.0 MiB | Exceeds GPU shared memory (48–96KB typical); forces DRAM on GPU; meaningful capacity hardness |
| 16.0 MiB | 16.0 MiB | 32 B | 524288 | 32 B | 32 B | 12 B | 32 B | 52 B | 16.0 MiB | Exceeds GPU shared memory (48–96KB typical); forces DRAM on GPU; meaningful capacity hardness |
| 20.0 MiB | 20.0 MiB | 32 B | 655360 | 32 B | 32 B | 12 B | 32 B | 52 B | 20.0 MiB | 32 GPU threads × 500 KB each = 16 MB shared; GPU must page; real DRAM latency enforced |
| 24.0 MiB | 24.0 MiB | 32 B | 786432 | 32 B | 32 B | 12 B | 32 B | 52 B | 24.0 MiB | Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness |
| 28.0 MiB | 28.0 MiB | 32 B | 917504 | 32 B | 32 B | 12 B | 32 B | 52 B | 28.0 MiB | Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness |
| 32.0 MiB | 32.0 MiB | 32 B | 1048576 | 32 B | 32 B | 12 B | 32 B | 52 B | 32.0 MiB | Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness |

## Detailed Per-Target Analysis

### 1.0 MiB Working Memory

```
blocks:               1.0 MiB  (32768 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:           1.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 1 MiB?** Fits in L3 cache — GPU SIMD trivially parallelizable; no meaningful memory hardness

### 2.0 MiB Working Memory

```
blocks:               2.0 MiB  (65536 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:           2.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 2 MiB?** May exceed L3 on some GPUs; modest cache pressure; dependency still primary cost

### 4.0 MiB Working Memory

```
blocks:               4.0 MiB  (131072 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:           4.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 4 MiB?** May exceed L3 on some GPUs; modest cache pressure; dependency still primary cost

### 12.0 MiB Working Memory

```
blocks:              12.0 MiB  (393216 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          12.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 12 MiB?** Exceeds GPU shared memory (48–96KB typical); forces DRAM on GPU; meaningful capacity hardness

### 16.0 MiB Working Memory

```
blocks:              16.0 MiB  (524288 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          16.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 16 MiB?** Exceeds GPU shared memory (48–96KB typical); forces DRAM on GPU; meaningful capacity hardness

### 20.0 MiB Working Memory

```
blocks:              20.0 MiB  (655360 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          20.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 20 MiB?** 32 GPU threads × 500 KB each = 16 MB shared; GPU must page; real DRAM latency enforced

### 24.0 MiB Working Memory

```
blocks:              24.0 MiB  (786432 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          24.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 24 MiB?** Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness

### 28.0 MiB Working Memory

```
blocks:              28.0 MiB  (917504 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          28.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 28 MiB?** Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness

### 32.0 MiB Working Memory

```
blocks:              32.0 MiB  (1048576 × 32 bytes)
seed:                    32 B  (SHA-256 of password + salt)
metadata:                12 B  (memory_kib u32, depth u32, passes u32)
temp_workspace:          32 B  (SHA-256 init scratch per block)
alignment:               52 B  (64-byte cache line rounding)
───────────────────────────────────────
total heap:          32.0 MiB
state (registers):       32 B  (4 × u64, not heap-allocated)
```

**What fails at 32 MiB?** Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness

## What Fails Without the Memory?

| Memory Removed | What Breaks |
|----------------|-------------|
| Blocks removed | Attacker can regenerate any block in O(1) with 1 SHA-256 call; no sequentiality enforced |
| Seed removed | Block contents become predictable; password binding lost |
| Metadata removed | Parameters can be forged; no config commitment |
| State removed | No sequential dependency; all steps become independent; trivially parallelizable |
| Memory <4 MiB | Fits in GPU shared memory; GPU batch attack trivially parallel |
| Memory <16 MiB | May fit in high-end GPU L2 cache; cache-hit attacks feasible |
| Memory >16 MiB | GPU forced to DRAM for random block reads; significant latency per step |
