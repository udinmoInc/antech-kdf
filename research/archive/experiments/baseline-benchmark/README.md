# Baseline Benchmark Laboratory

Contains baseline benchmarking logic for established password KDFs:
- Argon2id
- scrypt
- bcrypt
- PBKDF2-HMAC-SHA256

## Running Benchmarks
Run directly via CLI:
```bash
cargo run -p antech-kdf-cli -- benchmark --output research/results
```
