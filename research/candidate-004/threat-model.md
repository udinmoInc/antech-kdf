# Candidate-004 Threat Model

**Status: EXPERIMENTAL RESEARCH THREAT MODEL**

## 1. Defender Environment
- **Target Server**: 1 CPU core, 1 GB system RAM.
- **Working Set**: 16 MiB per active password verification request.
- **Concurrency**: 1 to 100 simultaneous authentication attempts.

## 2. Attacker Capabilities
- **Database Compromise**: Full access to stored password hashes (`$antech$v1$...`).
- **Attacker Hardware**: Multi-core CPUs (1..32 cores), high-end GPUs (24GB VRAM), and custom FPGA/ASIC hardware.
- **Knowledge**: Full source code, complete parameters, all salts, complete algorithmic specification.
- **Zero Hidden Secrets**: Candidate-004 operates as a pure symmetric KDF without server-secret dependencies.
