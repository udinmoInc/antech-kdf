# Antech KDF — Phase E.1 Candidate-E4 Audit

## 1. What Candidate-E4 Actually Is

Candidate-E4 combines Candidate-004's 16 MB u64 ARX memory churn core with a server secret seed mix and a simulated depth branch (`depth = 60` for correct vs `depth = 150` for wrong passwords).

## 2. What Is Measured

- Legitimate Correct Password Latency (Depth 60): 8.86 ms [MEASURED]
- Legitimate Wrong Password Latency (Depth 150): 11.91 ms [MEASURED]
- Informed Attacker Cracking Speed (Pruned at Depth 60): 279.3 qps [MEASURED]

## 3. What Is Modeled

- GPU Simulated Cracking Throughput (24GB VRAM): Modeled at 27934.1 qps [MODELED]

## 4. Prior Art & Comparison

Candidate-E4 reuses existing peppered KDF server-secret concepts and Candidate-004 memory churn. Its asymmetric depth parameter is an implementation artifact, not a cryptographic delayed distinguishability primitive.

## 5. Early-Rejection Attack

An offline attacker evaluating candidate passwords against a stolen hash executes depth=60 and checks for a digest match. Mismatching candidates are pruned immediately. The attacker NEVER incurs the depth=150 overhead. Thus, $A_{\text{guess}} = D_{\text{correct}} = 8.20\text{ ms}$, collapsing the claimed cost asymmetry.

## 6. Novelty Verdict & Candidate Status

### Final Status: **`EXISTING TECHNIQUE / NOT NOVEL`**

Candidate-E4 is **NOT NOVEL** and **FAILS** to provide cost asymmetry against an informed offline attacker.

## 7. What We Should Research Next

Abandon Candidate-E4's simulated depth asymmetry. Shift focus to **Phase F**: *Formal Specification of Candidate-004 (Family D)* as a pure, symmetric, low-resource bandwidth-hard KDF without unverified asymmetry claims.

