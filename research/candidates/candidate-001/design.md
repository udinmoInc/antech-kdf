# Candidate 001 Detailed Design

## Architectural Flow

1. **State Initialization**: Seed 1 MiB working buffer using PBKDF2/HMAC-SHA256 of password and salt.
2. **Bandwidth Churn Phase**: Execute $N$ rounds of non-linear pseudo-random reads and writes across the buffer to saturate L3 cache / memory bus bandwidth.
3. **Sequential Dependency Phase**: Forward-apply XOR rotation chain across working buffer.
4. **Final Digest Extraction**: Extract 256-bit derived key via zero-initialized reduction accumulator.

## Cryptographic Status Notice
Candidate 001 is an experimental research model. Security analysis against memory-time trade-off (TMTO) attacks is currently underway.
