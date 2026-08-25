# Threat Model — Antech KDF (Independent Review)

## Setting

Antech is a password-based key derivation / password hashing function. Typical deployment: a server stores self-describing hashes; an attacker later obtains that database and attempts offline password recovery.

**No server-held pepper or HSM secret is part of the current construction.** Do not assume one.

## Attacker capabilities (assumed)

The attacker has:

1. The **full algorithm specification** (this review package).
2. The **full source code** of production and research crates.
3. All **public parameters** embedded in each stored hash (`m`, `b`, `f`, `g`, `l`, salt).
4. A **stolen password database** of encoded hashes.
5. **Unlimited offline** guessing (bounded only by budget).
6. **Multicore CPUs**, consumer/server **GPUs**, and potential **FPGA/ASIC** resources.
7. Freedom to **rewrite and optimize** any evaluation strategy (memory layout, prefetch, batching, TMTO, pebbling, etc.), as long as the **digest matches** the specification for each guess.

The attacker does **not** need:

- Side-channel access to a live verifier (optional extra goal; see below).
- The original cleartext passwords (those are the attack objective).

## Security goals (what reviewers should try to break)

For a guess `P'` against stored `(Salt, Cfg, Digest)`:

1. **Correctness:** Any shortcut must still produce the same `Digest` as the normative `Derive`.
2. **Work:** Prefer attacks that reduce **total computational work** (mix operations, memory fills, energy, dollar cost) below a full honest evaluation.
3. **Memory:** Prefer attacks that reduce **peak attacker memory** without a compensating work blow-up that erases the gain (TMTO / pebbling).
4. **Amortization:** Prefer attacks that share work across many targets or many guesses.

Benchmark throughput alone is **not** a security proof. An optimized full evaluation can look “fast” while still doing the full cryptographic work.

## Non-goals / out of scope for the core claim

- TLS, authentication protocol design, UI phishing.
- Physical security of the server before theft.
- Claiming resistance to all future cryptanalysis.

## Asset

- Offline cost of testing one password guess against one salt/config (and amortised cost against many).

## Explicit non-reliance on obscurity

Graph constants, domain strings, and ARX parameters are public. Reviewers should assume the adversary knows them completely.
