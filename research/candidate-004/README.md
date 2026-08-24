# Candidate-004 — Family D: Dependency + Memory Churn KDF

**Status: EXPERIMENTAL RESEARCH KDF / NOT PRODUCTION READY**

## Overview
Candidate-004 is an experimental low-RAM, high-bandwidth, sequential-dependency password Key Derivation Function (KDF) designed for low-resource server deployments (~1 GB RAM, 1 CPU core).

## Core Principles
1. **Symmetric Execution**: Deterministic execution path for all inputs. Zero success/failure shortcuts.
2. **Bandwidth-Hard Churn**: u64 ARX memory updates across a 16 MiB working set to force DRAM bus traffic.
3. **Sequential Dependency**: $S_{i+1} = \text{ARX}(S_i, \text{Block}[S_i[0] \pmod N])$ prevents GPU thread scaling.
4. **Input Binding**: Cryptographically bound to password, salt, and parameters via SHA-256 seed expansion.
