# Argon2id Baseline Research

## Overview
Argon2id is the winner of the Password Hashing Competition (PHC) and the current gold standard for memory-hard password hashing (RFC 9106).

## Baseline Metrics (Target Profile: m=64MB, t=3, p=1)
- **Peak Memory**: 64 MiB per hash.
- **Server Latency**: ~30-50 ms.
- **Attacker Bottleneck**: Peak RAM cost on parallel GPU/ASIC crackers.

## Evaluation Goals
Measure baseline server concurrency limits under high login request loads (1, 10, 50, 100, 500, 1000 concurrent threads) to compare server memory pressure against low-RAM Antech candidates.
