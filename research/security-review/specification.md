# Antech KDF — Formal Specification (Review Target)

**Status:** Submitted for independent cryptanalysis. This document defines the **exact** construction under review.

**Do not** reconstruct the algorithm from optimized production source alone. If source and this specification disagree, treat the discrepancy as a review finding.

---

## 0. Canonical review target

Exactly one production construction is in scope:

| Field | Value |
|---|---|
| Public algorithm id | `antech` |
| Stored hash encoding | **v2** (`$antech$v2$…`) |
| Construction version (bound into seed) | **`CONSTRUCTION_VERSION = 4`** (u32 LE) |
| Default graph | **`CombinedFrontier`** (tag `g = 3`) |
| Default memory | **16 MiB** = 16384 KiB |
| Default block size | **32 bytes** |
| Default fan-in | **2** |
| Default salt length (when hashing) | **16 bytes** (CSPRNG) |
| Default output length | **32 bytes** |
| Mix rounds per parent pair | **`MIX_ROUNDS = 4`** |
| Frontier width constant | **`FRONTIER_WIDTH = 64`** |
| Tile blocks constant | **`TILE_BLOCKS = 512`** |
| Critical period | **`max(FRONTIER_WIDTH/16, 2) = 4`** |
| Tile length used by CombinedFrontier | **`min(TILE_BLOCKS, N) = 512`** at 16 MiB |
| Number of DAG nodes at default | **`N = memory_bytes / block_size = 524288`** |
| Rolling state | **four `u64` words** (256 bits), little-endian layout |
| Server-held secret | **None** (password + public salt + public parameters only) |

**Review target digest** = output of the procedure in §11–§12 under the default parameters above (or any valid parameter set explicitly stated by a vector).

Research-only graph kinds (`ReducedCriticalPath`, `CacheLocality`) and historical research modules under `research/code/antech-kdf-research/src/compute_memory*` are **out of scope** unless a reviewer deliberately studies them as contrast. They are **not** the canonical production default.

Public API entry points that wrap this construction (unchanged by this review package):

- `antech_kdf::hash` / `hash_with_config`
- `antech_kdf::verify`
- `antech_kdf::needs_rehash`

---

## 1. Inputs

| Symbol | Type | Meaning |
|---|---|---|
| `P` | byte string | Password (may be empty; may contain arbitrary bytes) |
| `Salt` | byte string | Salt, length `s` with `8 ≤ s ≤ 256` |
| `Cfg` | parameters | See §3 |

---

## 2. Outputs

| Symbol | Type | Meaning |
|---|---|---|
| `Digest` | `l` bytes | `8 ≤ l ≤ 128`. Default `l = 32`. Truncation/padding of the 32-byte SHA-256 finalize output as in §12. |

Encoded storage string (when using the library hasher): see §13.

---

## 3. Parameter domain

| Parameter | Symbol | Domain | Default |
|---|---|---|---|
| Memory | `m` (KiB) | `1024 … 1_048_576` | `16384` |
| Block size | `b` (bytes) | power of two, `≥ 16` | `32` |
| Fan-in | `f` | `2 … 8` | `2` |
| Graph tag | `g` | `1,2,3` | `3` (CombinedFrontier) |
| Output length | `l` | `8 … 128` | `32` |
| Salt length (hasher) | `s` | `8 … 256` | `16` |

Derived:

\[
N = \Bigl\lfloor \frac{1024\cdot m}{b}\Bigr\rfloor,\quad N \ge 64
\]

\[
\text{critical\_period} = \max(\lfloor FRONTIER\_WIDTH/16\rfloor, 2) = 4
\]

\[
\text{tile\_len} = \min(TILE\_BLOCKS, N)
\]

For CombinedFrontier parent selection, the implementation further uses

\[
\text{tile} = \max(\text{tile\_len},\; \min(TILE\_BLOCKS, 512))
\]

which equals `512` under default parameters.

---

## 4. Salt generation (library hasher)

When `hash` / `hash_with_config` is used:

1. Allocate `Salt` of length `Cfg.salt_length`.
2. Fill with CSPRNG bytes (`rand::thread_rng().fill_bytes`).
3. Derive `Digest` as below.
4. Encode per §13.

Independent implementations of the **KDF core** take `(P, Salt, Cfg)` as explicit inputs. Salt generation is not part of the mathematical KDF; it is part of the password-hashing API.

---

## 5. Domain separators and constants

```text
DOMAIN_SEED  = ASCII "antech-compute-memory-v4-seed"
DOMAIN_FINAL = ASCII "antech-compute-memory-v4-final"
DOMAIN_NODE0 = ASCII "antech-compute-memory-v2-node0"

CONSTRUCTION_VERSION = 4u32
MIX_ROUNDS = 4u32
FRONTIER_WIDTH = 64
TILE_BLOCKS = 512

C1 = 0xBF58476D1CE4E5B9
C2 = 0x94D049BB133111EB
GOLDEN = 0x9E3779B97F4A7C15
```

Graph tags:

| Graph | `g` |
|---|---|
| ReducedCriticalPath | 1 |
| CacheLocality | 2 |
| CombinedFrontier | 3 |

All multi-byte integers in hashes and encodings below are **little-endian** unless noted.

---

## 6. Initial seed binding

\[
\begin{aligned}
Seed &= \mathrm{SHA256}\big(\\
&\quad DOMAIN\_SEED \,\|\,
CONSTRUCTION\_VERSION_{le32} \,\|\,
g_{le32} \,\|\,\\
&\quad |P|_{le32} \,\|\, P \,\|\,
|Salt|_{le32} \,\|\, Salt \,\|\,\\
&\quad m_{le32} \,\|\, b_{le32} \,\|\, f_{le32} \,\|\,
MIX\_ROUNDS_{le32} \,\|\,\\
&\quad critical\_period_{le32} \,\|\, tile\_len_{le32}
\big)
\end{aligned}
\]

`Seed` is exactly 32 bytes.

---

## 7. Initial state

Interpret `Seed` as four little-endian `u64` words:

\[
S = (S[0], S[1], S[2], S[3])
= (\mathrm{LE64}(Seed[0..8]), \ldots, \mathrm{LE64}(Seed[24..32]))
\]

---

## 8. Memory layout

Allocate byte array `M` of length `1024\cdot m`, initialized to zero.

Block `i` (for `0 ≤ i < N`) occupies

\[
M[i\cdot b \,:\, (i+1)\cdot b]
\]

Under the default review target, `b = 32`, so each block is exactly the LE encoding of the four state words when written.

---

## 9. Phantom blocks (node 0 parents)

For each parent slot `t ∈ {0,…,f−1}` define phantom material:

\[
H_t = \mathrm{SHA256}(DOMAIN\_NODE0 \,\|\, Seed \,\|\, t_{le32})
\]

Let `Phantom[t]` be a `b`-byte buffer:

- Copy `min(b,32)` bytes from `H_t`.
- If `b > 32`, expand with the ARX stretch in production `node0_material` (see reference implementation). **Default review target uses `b = 32`, so no stretch is used.**

---

## 10. Parent selection — CombinedFrontier (canonical)

For node index `i = 0`, the parent set is empty; the engine uses phantoms instead (§11).

For `i ≥ 1`, compute `Parents(S, i)` as follows (matches `graph::combined`).

Notation: `push_unique(addr)` adds `addr` if `addr < i`, not already present, and length `< 8`.

1. Set `tile = max(tile_len, min(TILE_BLOCKS, 512))`, `tile_start = ⌊i / tile⌋ · tile`.
2. `critical = (i % critical_period == 0) OR (i % FRONTIER_WIDTH == 0)`.
3. **Local frontier (target 2 parents):**
   - `push_unique(i−1)`
   - `fw = min(FRONTIER_WIDTH, i)`
   - `push_unique(i−1 − ((S[0] as usize) mod fw))`
   - Fill remaining up to 2 with mixes:
     \[
     mix = S[\ell \bmod 4] \oplus (i\cdot GOLDEN),\quad
     slot = (mix \bmod fw),\quad
     push\_unique(i−1−slot)
     \]
     with a small guard loop as in source (break if no progress).
4. If `i > tile_start + 1`:
   \[
   push\_unique\big(tile\_start + ((S[1] \bmod (i-tile\_start)))\big)
   \]
5. If `i > fw + 1` with `remote_span = i − fw`:
   - If `critical` OR `i` even: `push_unique(((S[1] ⊕ rotl(S[3],11)) mod remote_span))`
   - If `critical`: `push_unique(((S[0] ⊕ GOLDEN) mod remote_span))`
6. While `|Parents| < f` and guard `< 4`, add tile-local or `[0,i)` addresses from
   \[
   mix = S[\ell \bmod 4] \oplus (i\cdot GOLDEN)
   \]
7. **Dual far-scatter destinations** (if `i > fw`, `span = i − fw`):
   \[
   \begin{aligned}
   d_1 &= (S[2] \oplus GOLDEN) \bmod span \\
   d_2 &= (S[3] \oplus \mathrm{rotl}(S[0],7)) \bmod span
   \end{aligned}
   \]

Return parent index list (length between 1 and `f`, typically), plus optional `(d_1, d_2)`.

> Other graph kinds are defined in `crates/antech-kdf-core/src/graph.rs` but are **not** the default review target.

---

## 11. State transition and memory writes

Let `load64(B, off)` read 8 little-endian bytes from block `B` at offset `off`, or `0` if out of range.

### 11.1 Pair mix `MixPair(S, B₁, B₂)`

For round `r = 0 … MIX_ROUNDS−1`, with `rr = r` as `u64`:

\[
\begin{aligned}
S[0] &\leftarrow \mathrm{rotl}_{13}\big(S[0] + (b10 \oplus (b20 + rr))\big) \oplus S[3] \\
S[1] &\leftarrow \mathrm{rotl}_{17}\big(S[1] + (b11\cdot C1 \oplus b21)\big) \oplus S[0] \\
S[2] &\leftarrow \mathrm{rotl}_{19}\big(S[2] + (b12 \oplus b22\cdot C2)\big) \oplus S[1] \\
S[3] &\leftarrow \mathrm{rotl}_{23}\big(S[3] + (b13 + b23 \oplus GOLDEN\cdot(rr+1))\big) \oplus S[2]
\end{aligned}
\]

where `b1j = load64(B₁, 8j)`, `b2j = load64(B₂, 8j)` for `j ∈ {0,1,2,3}`, and `+`, `·` are wrapping `u64` operations.

### 11.2 Parent fold `MixViews(S, V[0..n))`

- If `n = 0`: no-op.
- If `n = 1`: `MixPair(S, V[0], V[0])`.
- Else: for `k = 0,2,4,…` while `k+1 < n`: `MixPair(S, V[k], V[k+1])`; if one view remains, `MixPair(S, V[last], V[last])`.

### 11.3 Main loop

```
S ← StateFromSeed(Seed)
allocate M[0 .. 1024*m) ← 0
for i ← 0 .. N-1:
    if i = 0:
        V ← [Phantom[0], …, Phantom[f-1]]
    else:
        (Parents, d1, d2) ← CombinedFrontierParents(S, i, f, …)
        V ← [ M[p] for p in Parents ]   // current bytes of those blocks
    MixViews(S, V)
    // Write pristine block i from state
    M[i] ← LE-encode(S) truncated/padded to b bytes
    // Dual scatter: XOR state into historical blocks
    if d1 defined and d1 < N and d1 ≠ i:
        M[d1] ← M[d1] ⊕ LE-encode(S)   // XOR first min(b,32) bytes from state words
    if d2 defined and d2 < N and d2 ≠ i:
        M[d2] ← M[d2] ⊕ LE-encode(S)
```

After node `i`, the rolling state `S` is the state used for parent selection at node `i+1`.

**Important:** Scatters mutate previously written blocks. Any later read of those blocks sees the XOR-updated contents. A reduced-memory evaluator that discards blocks without replaying scatters is incorrect.

---

## 12. Finalization

After the loop, let `Last = M[N−1]` (full `b` bytes) and `S` be the final state.

\[
\begin{aligned}
D_{32} &= \mathrm{SHA256}\big(
DOMAIN\_FINAL \,\|\,
CONSTRUCTION\_VERSION_{le32} \,\|\,
g_{le32} \,\|\,
Seed \,\|\,
S[0]_{le64}\,\|\,S[1]_{le64}\,\|\,S[2]_{le64}\,\|\,S[3]_{le64} \,\|\,
Last
\big)
\end{aligned}
\]

Then:

- If `l < 32`: `Digest = D_{32}[0..l)`.
- If `l = 32`: `Digest = D_{32}`.
- If `l > 32`: `Digest = D_{32} \| 0^{l−32}` (zero-pad).

Default review target: `l = 32`, so `Digest = D_{32}`.

---

## 13. Encoding (v2)

```text
$antech$v2$m=<m>,s=<|Salt|>,b=<b>,f=<f>,g=<g>,l=<|Digest|>$<salt_hex>$<digest_hex>
```

- `<salt_hex>` / `<digest_hex>`: lowercase hex of raw bytes.
- `g` is the numeric graph tag (CombinedFrontier ⇒ `3`).

---

## 14. Verification procedure

Given password `P` and encoded string `E`:

1. Parse `E` → `(Cfg', Salt, Digest*)`. Reject unknown versions (e.g. `v1`).
2. Compute `Digest = Derive(P, Salt, Cfg')` as in §§6–12.
3. Compare `Digest` and `Digest*` in **constant time**. Accept iff equal and lengths match.

---

## 15. Pseudocode summary

```
function Derive(P, Salt, Cfg):
    Seed ← BindSeed(P, Salt, Cfg)           // §6
    S ← StateFromSeed(Seed)                 // §7
    M ← zeros(Cfg.memory_bytes)
    Ph ← Phantoms(Seed, Cfg.fan_in, Cfg.block_size)
    for i in 0 .. N-1:
        if i == 0: V ← Ph
        else:      V ← gather(M, Parents(S,i))
        S ← MixViews(S, V)                  // §11
        write_block(M, i, S)
        apply_scatters(M, S, scatter_dests(S,i))
    return Finalize(Seed, S, M[N-1], Cfg)   // §12
```

---

## 16. Normative source map

| Spec section | Production source |
|---|---|
| Parameters | `antech-kdf-types` `AntechConfig` |
| Seed / finalize | `antech-kdf-core` `state.rs` |
| MixPair / phantoms | `antech-kdf-core` `mixing.rs` |
| CombinedFrontier | `antech-kdf-core` `graph.rs` `combined` |
| Main loop | `antech-kdf-core` `engine.rs` `AntechEngine::derive` |
| Encoding | `antech-kdf-format` |
| Public API | `antech-kdf` |

Readable independent reimplementation: [`reference/`](./reference/).

Test vectors: [`test-vectors.json`](./test-vectors.json).
