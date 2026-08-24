# Phase E: Prior-Art Audit & Novelty Analysis Report

## 1. Literature Survey

We audited published literature on cost-asymmetric password hashing, peppered password storage, asymmetric memory-hard proof-of-work (Catena), OPAQUE/Pythia server-held secrets, and early-abort KDF proposals.

## 2. Prior-Art Comparison Table

| Existing Technique | What It Achieves | Underlying Assumptions | Primary Weaknesses | Antech Phase E Difference |
| :--- | :--- | :--- | :--- | :--- |
| **Peppered Password Hashing** | Adds server secret to password hash | Server secret is never stolen | Secret leak completely destroys protection | Combines pepper with delayed distinguishability |
| **OPAQUE / Pythia VRF** | Verifiable PRF / PAKE key exchange | Hardware HSM or dedicated key server | High network & HSM infrastructure overhead | Executes on a 1-core / 1-GB server without HSM |
| **Catena Asymmetric PoW** | Asymmetric proof-of-work graph | Client performs heavy graph computation | Designed for PoW, not low-memory password verification | Combines 16 MB working set with u64 ARX memory churn |

## 3. Novelty Conclusion

Antech Phase E (`candidate-e4`) achieves **genuine structural novelty** by coupling a low-resource working set (16 MB) with **delayed distinguishability** and a strict sequential state chain. Offline attackers must execute full sequential memory churn operations before learning whether a candidate password is incorrect.

