# Contributing to Antech KDF

Thank you for your interest in contributing to **Antech KDF**. We welcome contributions from engineers, cryptographers, and performance researchers.

---

## 🛠️ Development & Building

### Prerequisites
* **Rust Toolchain**: Rust 1.70 or newer (`cargo`, `rustc`)

### Building Workspace

```bash
# Clone the repository
git clone https://github.com/udinmoInc/antech-kdf.git
cd antech-kdf

# Build workspace targets in debug mode
cargo build --workspace

# Build workspace targets in release mode
cargo build --release --workspace
```

---

## 🏗️ Repository Code Structure Rules

The codebase is organized into clear functional crates to separate stable interfaces from experimental research:

```text
crates/
├── antech-kdf/          # Stable Public Developer API (hash, verify, needs_rehash)
├── antech-kdf-core/     # Reusable Core Primitives & Memory Allocation
├── antech-kdf-format/   # $antech$v1$... String Encoder & Parser
├── antech-kdf-types/    # Shared Parameter & Error Structures
└── antech-kdf-research/ # Active Research Candidates, Attacker Tools & Benchmarks
```

* **Core vs. Research Separation**: Reusable, stable logic belongs in `antech-kdf-core`. Experimental candidate variants (Variant K1, Variant K2), CPU/GPU attacker frameworks, and benchmark runners belong exclusively in `antech-kdf-research`.
* **Public API Integrity**: The public API (`hash`, `verify`, `needs_rehash`) must remain strictly unchanged.

---

## 🧪 Testing & Code Quality Guidelines

Before submitting a pull request, ensure all verification commands pass cleanly:

```bash
# 1. Verify workspace compilation
cargo check --workspace

# 2. Verify workspace test targets
cargo check --workspace --tests

# 3. Check code formatting
cargo fmt --all -- --check

# 4. Run workspace linter
cargo clippy --workspace
```

---

## 📊 Benchmark Reproducibility Guidelines

When contributing performance measurements, benchmarks, or attacker models:

1. **Hardware Telemetry**: Record host CPU model, physical core count, logical thread count, system RAM, OS, compiler version, and GPU model. Save environment details in `research/data/hardware.md`.
2. **Fair Comparison**: Do not modify baseline algorithms (Argon2id, scrypt) while evaluating Antech variants.
3. **Data Classification**: Explicitly distinguish `MEASURED` physical execution from `MODELED` theoretical bounds or `UNAVAILABLE` metrics.
