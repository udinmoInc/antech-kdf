# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-08-24

### Added
- Initial workspace scaffold for Antech KDF research project.
- Tiny 3-function public API (`hash`, `verify`, `needs_rehash`).
- Internal workspace crates: `antech-kdf-core`, `antech-kdf-format`, `antech-kdf-types`, `antech-kdf-ffi`, `antech-kdf-cli`.
- Self-describing hash format (`$antech$v1$...`).
- C ABI layer (`antech_hash`, `antech_verify`, `antech_needs_rehash`, `antech_free`).
- Research workspace directory structure (`baselines/`, `candidates/`, `experiments/`, `attacker/`).
- Criterion benchmark scaffolding, fuzz targets, integration tests, and documentation suite.
