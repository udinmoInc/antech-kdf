# Antech KDF — Repository-Wide Configuration Audit Report

This document records the comprehensive audit of all constants and hardcoded parameters across the **Antech KDF** repository (`crates/antech-kdf`, `antech-kdf-core`, `antech-kdf-format`, `antech-kdf-types`, and `antech-kdf-research`).

---

## 📊 Configuration Classification Matrix

Every audited value is classified into one of six categories:
1. **PROTOCOL CONSTANT**: Fixed cryptographic primitives, domain-separated strings, or magic header tags (Retained as fixed constants).
2. **SAFETY LIMIT**: Hard validation bounds for parameters like memory size and salt length (Enforced via type validators).
3. **DEFAULT**: System defaults configurable via `AntechConfig::default()`.
4. **RESEARCH PARAMETER**: Configurable research candidate settings (`ResearchParams`, `VariantK1`, `VariantK2`).
5. **BENCHMARK PARAMETER**: Attacker worker counts, batch sizes, and TMTO percentage sweeps.
6. **ACCIDENTAL HARDCODE**: Hardcoded logic moved into runtime configuration objects.

---

## 🔍 Complete Audit Findings Table

| Value / Parameter | File Location | Classification | Action Taken |
| :--- | :--- | :--- | :--- |
| `b"antech-v1-domain-separator"` | `crates/antech-kdf-core/src/engine.rs` | **PROTOCOL CONSTANT** | Retained as fixed cryptographic domain separator label. |
| `b"antech-v1-domain-separator-variant-k1"` | `crates/antech-kdf-research/src/candidates/k1.rs` | **PROTOCOL CONSTANT** | Retained as fixed candidate domain separator label. |
| `b"antech-v1-domain-separator-variant-k2"` | `crates/antech-kdf-research/src/candidates/k2.rs` | **PROTOCOL CONSTANT** | Retained as fixed candidate domain separator label. |
| `[13, 17, 19, 23]` ARX Shifts | `crates/antech-kdf-core/src/engine.rs` | **PROTOCOL CONSTANT** | Retained as fixed 4-round ARX rotation shift constants. |
| `32` bytes (SHA-256 Digest Output) | `crates/antech-kdf-core/src/engine.rs` | **PROTOCOL CONSTANT** | Retained as fixed SHA-256 block size. |
| `$antech$` Magic Header | `crates/antech-kdf-format/src/encoder.rs` | **PROTOCOL CONSTANT** | Retained as fixed serialized string header tag. |
| `v1` Version Identifier | `crates/antech-kdf-format/src/encoder.rs` | **PROTOCOL CONSTANT** | Retained as fixed algorithm format version string. |
| `8`..`256` bytes (Salt Length) | `crates/antech-kdf-types/src/config.rs` | **SAFETY LIMIT** | Validated via `SaltLength::validate()`. |
| `1`..`1024` MiB (Memory Bounds) | `crates/antech-kdf-types/src/config.rs` | **SAFETY LIMIT** | Validated via `MemorySize::validate()`. |
| `8`..`128` bytes (Output Bounds) | `crates/antech-kdf-types/src/config.rs` | **SAFETY LIMIT** | Validated via `OutputLength::validate()`. |
| `16384` KiB (Default RAM) | `crates/antech-kdf-types/src/config.rs` | **DEFAULT** | Configurable via `AntechConfig::builder().memory_mib()`. |
| `16` bytes (Default Salt Length) | `crates/antech-kdf-types/src/config.rs` | **DEFAULT** | Configurable via `AntechConfig::builder().salt_length()`. |
| `650,000` steps (K1 Depth) | `crates/antech-kdf-research/src/candidates/k1.rs` | **RESEARCH PARAMETER** | Decoupled into `ResearchParams` configuration object. |
| `550,000` steps (K2 Depth) | `crates/antech-kdf-research/src/candidates/k2.rs` | **RESEARCH PARAMETER** | Decoupled into `ResearchParams` configuration object. |
| `128 MB` Global Memory Ceiling | `crates/antech-kdf-core/src/resource.rs` | **DEFAULT** | Configurable via `ResourcePolicy { max_memory_kib }`. |
| `64` Max Active KDF Jobs | `crates/antech-kdf-core/src/resource.rs` | **DEFAULT** | Configurable via `ResourcePolicy { max_active_jobs }`. |
| Worker Threads (`1, 4, 16, 32`) | `crates/antech-kdf-research/src/attackers/cpu.rs` | **BENCHMARK PARAMETER** | Controlled via CPU benchmark runner. |
| GPU Max Threads (`125, 500`) | `crates/antech-kdf-research/src/attackers/cuda.rs` | **BENCHMARK PARAMETER** | Controlled via GPU spatial bounds framework. |

---

## ⚖️ Rationale for Retained Protocol Constants

1. **Cryptographic Domain Separators**: String labels like `b"antech-v1-domain-separator"` ensure cryptographic domain isolation. Making domain tags user-configurable would create security vulnerabilities where different parameters collide.
2. **Internal ARX Bitwise Shifts**: Rotation constants (`13`, `17`, `19`, `23`) define the diffusion properties of the ARX mixing function. Changing shift amounts dynamically would alter the underlying mathematical primitive.
3. **Format Identifiers**: Header tags (`$antech$v1$...`) ensure deterministic string parsing across different software versions.
