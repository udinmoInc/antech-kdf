# Research Candidate 001: Bandwidth-Hard Low-RAM Churn

> **STATUS**: `EXPERIMENTAL`  
> **WARNING**: *Not production safe. Under active cryptographic evaluation.*

## Overview

Candidate 001 explores reducing peak RAM consumption to 1-64 MB while maintaining high attacker latency and cost through sustained memory bus bandwidth churn and strict sequential dependency constraints.

## Candidate Metadata

- **Candidate ID**: Candidate-001
- **Status**: `EXPERIMENTAL`
- **Hypothesis**: Low peak memory + high latency + sustained memory bandwidth churn yields equal attacker economic penalty as large peak memory.
- **Expected Benefit**: 10x-50x lower server peak memory usage, enabling higher concurrent login capacity without DoS risk.
- **Threat Model**: Offline brute-force dictionary attack on derived hashes using high-end GPUs, multi-core CPUs, and customized ASICs.
- **Known Weaknesses**: Low peak RAM allows high spatial concurrency on GPUs if bandwidth utilization is not memory bus saturated.
- **Measurements**: Initial baseline benchmark pending.
- **Attack Results**: Formal ASIC/GPU model under construction.
