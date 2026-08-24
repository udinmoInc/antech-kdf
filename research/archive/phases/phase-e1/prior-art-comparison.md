# Candidate-E4 Prior-Art & Cryptographic Comparison

| Property | Existing Cost-Asymmetric Method | Candidate-E4 Method | Novel Cryptographic Contribution? | Security Implication |
| :--- | :--- | :--- | :--- | :--- |
| Asymmetric Verification Path | Catena / Asymmetric PoW graph evaluation | Simulated boolean parameter branching (depth 60 vs 150) | NO | Attacker prunes wrong guesses at depth 60; asymmetry collapses |
| Server Secret / Pepper | Standard Pepper / OPAQUE VRF server secret | HMAC Sha256 seed mix with server_secret | NO | Standard server-secret dependency; protection disappears if stolen |
| Memory Churn Core | Argon2 / Candidate-004 u64 ARX | Candidate-004 16MB u64 ARX memory churn | NO | Reuses Phase C/D Candidate-004 core without new primitive |
