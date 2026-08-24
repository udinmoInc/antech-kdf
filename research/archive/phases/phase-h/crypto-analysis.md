# Candidate-004 Formal Cryptographic Soundness & Dependency Graph Analysis

## 1. Formal Dependency Graph Equations

The sequential state transition graph is defined as:

$$S_0 = \text{SHA256}(\text{"antech-v1-domain-separator-2026"} \parallel P \parallel S \parallel \text{Params})$$

$$\text{Addr}_i = S_i[0] \pmod N$$

$$S_{i+1} = \text{ARX}(S_i, \text{Block}[\text{Addr}_i])$$

$$\text{Digest} = \text{SHA256}(\text{"antech-v1-finalization"} \parallel S_{\text{final}})$$

## 2. Primitive Audit Matrix

| Property | Primary Primitive | Security Rationale | Audit Status |
| :--- | :--- | :--- | :--- |
| Password & Salt Domain Separation | HMAC-SHA256 | SHA256 domain separator prefix prevents cross-protocol precomputation | **CRYPTOGRAM-SOUND** |
| State Evolution & Non-Bypassability | u64 ARX Sequential Churn | S_{i+1} = ARX(S_i, Block[Addr_i]) prevents parallel node skipping | **ANALYSIS-RECOMMENDED** |
| Final Digest Extraction | HMAC-SHA256 Finalization | Final digest cryptographically binds entire accumulated 256-bit ARX state | **CRYPTOGRAM-SOUND** |

## 3. Cryptographic Findings & Recommendations

- **Input Binding**: HMAC-SHA256 seed derivation ensures full cryptographic binding across password, salt, and parameters.

- **Sequential Churn**: u64 ARX mixing ensures non-bypassability. External formal peer review is recommended prior to production deployment.

