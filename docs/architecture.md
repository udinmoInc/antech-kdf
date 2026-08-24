# Antech KDF — System Architecture & Layering

This document describes the modular architecture of **Antech KDF**, detailing how public API calls flow through core cryptographic primitives, research candidate engines, and memory management controllers.

---

## 🏗️ Layered System Architecture

```mermaid
graph TD
    subgraph Layer1 ["1. Public API Crate (crates/antech-kdf)"]
        API["hash() / verify() / needs_rehash()"]
    end

    subgraph Layer2 ["2. Core Primitive Layer (crates/antech-kdf-core & antech-kdf-format)"]
        ENGINE["core_hash() / core_verify()"]
        FMT["Format Encoder & Parser ($antech$v1$...)"]
        SALT["OsRng Secure 16-byte Salt Generation"]
        MEM["Buffer Allocation (16 MB / 64 MB)"]
    end

    subgraph Layer3 ["3. Research Laboratory Crate (crates/antech-kdf-research)"]
        CAND["Candidate-004 Symmetric Core"]
        K1["Variant K1: Dynamic S-Box State Feedback"]
        K2["Variant K2: Quad-Node TMTO Graph"]
        CTRL["ResourceController (128 MB Global Ceiling)"]
    end

    subgraph Layer4 ["4. Attack & Benchmark Suite"]
        CPU["cpu_attacker (Multi-worker SIMD Cracking)"]
        CUDA["gpu_attacker (CUDA GPU Spatial Bounds)"]
        TMTO["tmto (Recomputation Multipliers)"]
    end

    API --> ENGINE
    ENGINE --> FMT
    ENGINE --> SALT
    ENGINE --> MEM
    ENGINE --> CAND
    CAND --> K1
    CAND --> K2
    MEM --> CTRL
    K1 --> CPU
    K2 --> CPU
    K1 --> CUDA
    K2 --> TMTO
```

---

## 📦 Workspace Crate Taxonomy

| Crate Path | Primary Purpose | Exported Symbols |
| :--- | :--- | :--- |
| [`crates/antech-kdf`](file:///f:/Coding/experiments/antech-kdf/crates/antech-kdf) | Stable Developer API | `hash()`, `verify()`, `needs_rehash()`, `Error` |
| [`crates/antech-kdf-core`](file:///f:/Coding/experiments/antech-kdf/crates/antech-kdf-core) | Core Engines & Memory Allocation | `core_hash()`, `core_verify()`, `CoreError` |
| [`crates/antech-kdf-format`](file:///f:/Coding/experiments/antech-kdf/crates/antech-kdf-format) | Serialization & Encoding | `encode_hash()`, `parse_hash()`, `HashFormat` |
| [`crates/antech-kdf-types`](file:///f:/Coding/experiments/antech-kdf/crates/antech-kdf-types) | Parameter & Error Structures | `KdfParams`, `AlgorithmVersion` |
| [`crates/antech-kdf-research`](file:///f:/Coding/experiments/antech-kdf/crates/antech-kdf-research) | Laboratory Candidates & Benchmarks | `Candidate004`, `VariantK1`, `VariantK2`, `run_research_suite()` |

---

## ⚙️ Memory Pipeline Architecture

```mermaid
sequenceDiagram
    autonumber
    participant Client as Application Client
    participant Core as Core Engine
    participant OsRng as OS Random Generator
    participant Memory as 16 MB Buffer Allocator
    participant Research as Variant K1 / K2 ARX Step

    Client->>Core: core_hash("password")
    Core->>OsRng: Generate 16-byte random salt
    OsRng-->>Core: Salt bytes
    Core->>Memory: Allocate contiguous 16 MB buffer
    Memory-->>Core: Zeroed Buffer Slice
    Core->>Research: Execute sequential ARX state mixing
    Research-->>Core: 256-bit Output Digest
    Core->>Client: $antech$v1$m=16384,t=650000...
```
