# Candidate-E4 Code Reconstruction & Execution Flow

## 1. Parameters & Memory Layout

- Working Set: 16 MB
- u64 Block Count: 524288
- Correct Scenario Depth: 60 rounds
- Wrong Scenario Depth: 150 rounds

## 2. Precise Execution Flow Diagram

```text
password + salt + [server_secret]
            ↓
   Sha256 Seed (32 bytes)
            ↓
State Init: u64x4 [s0, s1, s2, s3]
            ↓
Branching: if is_correct_password_scenario { depth = 60 } else { depth = 150 }
            ↓
u64 ARX Memory Churn Loop (60 or 150 rounds)
            ↓
Sha256 Final Output Digest
```

## 3. Asymmetry Mechanism Audit

- **Finding**: Asymmetry is simulated by inspecting `params.is_correct_password_scenario`. A legitimate server cannot know in advance whether an input password is correct, while an offline attacker tests guesses against stored hashes by executing depth=60 and pruning mismatching candidates immediately.
