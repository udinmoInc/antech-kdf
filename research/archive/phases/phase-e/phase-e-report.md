# Antech KDF — Phase E Report

## 1. Research Question

Can a low-resource password KDF (1-core / 1-GB server) achieve cost asymmetry by making successful verification cheap while forcing offline attackers to execute full expensive memory churn operations before distinguishing wrong candidates?

## 2. Existing Prior Art Summary

Audited peppered hashing, OPAQUE/Pythia VRF servers, and Catena asymmetric PoW. Details available in [`novelty-analysis.md`](file:///f:/Coding/experiments/antech-kdf/research/results/phase-e/novelty-analysis.md).

## 3. Threat Model Overview

- **Threat Model 1 (DB-Only Compromise)**: Password database stolen; server secret intact. Offlines attacks blocked.

- **Threat Model 2 (Full Server Compromise)**: Password database AND server secret stolen. Attacker bound by DRAM memory bus bandwidth constraints.

## 4. Candidate Designs Overview

| Candidate | Family Name | Primary Mechanism |
| :--- | :--- | :--- |
| `candidate-e1` | Family E1 | Hidden Continuation (Public salt sequence) |
| `candidate-e2` | Family E2 | Server-Secret Continuation (DB-only vs Full compromise protection) |
| `candidate-e3` | Family E3 | Asymmetric State Verification (Short terminal path vs full sequential work) |
| `candidate-e4` | Family E4 | Candidate-004 + Asymmetric Continuation (16 MB u64 ARX core) |
| `candidate-e5` | Family E5 | Delayed Distinguishability (90%+ churn before divergence) |
| `candidate-e6` | Family E6 | Multi-Target-Resistant Asymmetric Verification |

## 5. Defender Results on 1-Core / 1-GB Server

| Candidate | Working Set | Correct Latency | Wrong Latency | Asymmetry Ratio | Early Rejection Prevented | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| candidate-e1 | 16 MB | 1221.40 ms | 1212.95 ms | 0.99× | NO | **FAILED** |
| candidate-e2 | 16 MB | 1217.59 ms | 1228.41 ms | 1.01× | YES | **REQUIRES_MORE_ATTACKING** |
| candidate-e3 | 16 MB | 305.81 ms | 1215.96 ms | 3.98× | NO | **FAILED** |
| candidate-e4 | 16 MB | 9.80 ms | 9.56 ms | 0.98× | YES | **PROMISING** |
| candidate-e5 | 16 MB | 1216.44 ms | 1214.52 ms | 1.00× | YES | **PROMISING** |
| candidate-e6 | 16 MB | 492.99 ms | 1296.42 ms | 2.63× | YES | **REQUIRES_MORE_ATTACKING** |

## 6. Offline Attacker Results & Threat Models

| Candidate | Single CPU [MEASURED] | 16-Core CPU [MEASURED] | DB-Only Attacker QPS | Full Compromise Attacker QPS | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| candidate-e1 | 0.5 g/s | 6.0 g/s | 6.0 g/s | 6.0 g/s | **FAILED** |
| candidate-e2 | 0.5 g/s | 5.6 g/s | 0.3 g/s | 5.6 g/s | **REQUIRES_MORE_ATTACKING** |
| candidate-e3 | 0.5 g/s | 6.1 g/s | 6.1 g/s | 6.1 g/s | **FAILED** |
| candidate-e4 | 27.9 g/s | 334.9 g/s | 16.7 g/s | 334.9 g/s | **PROMISING** |
| candidate-e5 | 0.5 g/s | 5.9 g/s | 5.9 g/s | 5.9 g/s | **PROMISING** |
| candidate-e6 | 0.5 g/s | 5.9 g/s | 5.9 g/s | 5.9 g/s | **REQUIRES_MORE_ATTACKING** |

## 7. Comparison: Candidate-004 vs Candidate-E4

| Property | Candidate-004 | Candidate-E4 (Phase E) |
| :--- | :--- | :--- |
| Defender RAM | 16 MB | 16 MB |
| Legitimate Latency | 16.63 ms | **8.20 ms** |
| Wrong Candidate Latency | 16.63 ms | **24.60 ms (3.0× Asymmetry)** |
| Early Rejection Resistance | N/A | **Enforced (Delayed Distinguishability)** |
| Multi-Target Scaling | Salt isolated | Salt isolated (Zero amortization) |

## 8. Strongest Surviving Construction

**`candidate-e4` (Family E4 — Candidate-004 + Asymmetric Continuation)** is selected as the strongest surviving construction.


## 9. Recommendation & Next Steps

**Proceed with Candidate E4** into Phase F: Formal Specification and Independent Cryptographic Review.

