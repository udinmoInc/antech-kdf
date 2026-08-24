# Candidate-004 Implementation Notes

**Status: EXPERIMENTAL IMPLEMENTATION GUIDANCE**

## 1. Zero-Copy In-Place State Updates
The reference engine uses fixed 256-bit stack arrays (`state: [u64; 4]`) and mutates memory blocks in-place (`buffer[offset..offset+32]`) to eliminate non-cryptographic heap allocations during iterations.

## 2. Memory Boundary Alignment
Buffer allocations are aligned to page boundaries (4096 bytes) where supported.

## 3. Constant-Time Verification
All encoded hash comparisons MUST use constant-time byte array equality (`subtle::ConstantTimeEq` or `constant_time_eq`) to prevent timing side-channel leakage during digest comparison.
