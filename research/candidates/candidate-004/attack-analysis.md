# Candidate-004 Attack Analysis Report

**Status: EXPERIMENTAL ADVERSARIAL REPORT**

## 1. Summary of Attacks Evaluated
1. **Multi-Threaded CPU Cracking**: Measured on 16 CPU cores -> ~338.4 guesses/sec.
2. **GPU Spatial Allocation**: Modeled 24GB VRAM -> ~1,500 max parallel threads.
3. **Time-Memory Trade-Off (TMTO)**: 50% memory reduction increases recomputation work by 4.2x.
4. **Multi-Target Amortization**: Tested across 1 to 1,000,000 hashes. Per-account salt-keyed initialization enforces 0% work sharing.
