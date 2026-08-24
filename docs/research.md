# Antech KDF — Research Documentation Navigation Guide

This document links the core documentation to the 7-chapter paper-style research documentation and research dataset files.

---

## 🗺️ Research Paper Navigation Map

```mermaid
graph LR
    subgraph Paper ["Paper-Style Research (research/)"]
        P1["01-problem.md"]
        P2["02-background.md"]
        P3["03-design.md"]
        P4["04-evaluation.md"]
        P5["05-security.md"]
        P6["06-limitations.md"]
        P7["07-future-work.md"]
    end

    subgraph Datasets ["Datasets (research/data/)"]
        DATA["baseline.csv<br/>defender.csv<br/>attacker.csv<br/>tmto.csv"]
        HW["hardware.md"]
    end

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P5 --> P6
    P6 --> P7
    P4 --> DATA
    P4 --> HW
```

---

## 📖 Chapter Directory

* [**Chapter 1: The Problem**](file:///f:/Coding/experiments/antech-kdf/research/01-problem.md) — Server RAM cost, VPS bounds, 16 MB hypothesis.
* [**Chapter 2: Background**](file:///f:/Coding/experiments/antech-kdf/research/02-background.md) — Argon2id baseline, scrypt, bcrypt, PBKDF2.
* [**Chapter 3: Design**](file:///f:/Coding/experiments/antech-kdf/research/03-design.md) — Candidate-004 core, Variant K1 & K2 design.
* [**Chapter 4: Evaluation**](file:///f:/Coding/experiments/antech-kdf/research/04-evaluation.md) — Measured comparative results (16 MB vs 64 MB).
* [**Chapter 5: Security**](file:///f:/Coding/experiments/antech-kdf/research/05-security.md) — Adversarial cost modeling, TMTO, multi-target.
* [**Chapter 6: Limitations**](file:///f:/Coding/experiments/antech-kdf/research/06-limitations.md) — Pending CUDA GPU measurements, ASIC bounds.
* [**Chapter 7: Future Work**](file:///f:/Coding/experiments/antech-kdf/research/07-future-work.md) — Physical CUDA execution roadmap, audit plans.
