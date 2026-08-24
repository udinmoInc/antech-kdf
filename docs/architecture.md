# Antech KDF Architecture

## System Diagram

```
                 APPLICATION
                      │
                      ▼
              ┌───────────────┐
              │   antech-kdf  │
              │               │
              │ hash()        │
              │ verify()      │
              │ needs_rehash()│
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │  antech-core  │
              │               │
              │ version       │
              │ format        │
              │ salt          │
              │ engine        │
              │ memory        │
              │ bandwidth     │
              └───────┬───────┘
                      │
                      ▼
              Research Engine
                      │
                      ▼
              H1 Candidate
```

## Internal Crate Responsibilities

- **`antech-kdf`**: Main application interface. Exposes *only* 3 functions (`hash`, `verify`, `needs_rehash`).
- **`antech-kdf-core`**: Core engine dispatch, memory zeroization, bandwidth simulation, version checking, constant-time comparison, salt generation.
- **`antech-kdf-format`**: Serializes and parses `$antech$v1$m=...,t=...,p=...,bw=...$<salt>$<digest>`.
- **`antech-kdf-types`**: Shared types across core and format crates.
- **`antech-kdf-ffi`**: C ABI exporting C functions.
- **`antech-kdf-cli`**: Command line interface.
