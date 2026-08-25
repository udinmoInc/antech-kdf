# Research third-party (not Antech)

External baselines used only for **research comparisons**. Not part of the Antech KDF library, not a production dependency, and never linked from `crates/`.

## argon2-gpu (WebDollar)

Optional CUDA Argon2id reference for GPU attacker head-to-head vs Antech.

- Upstream: https://github.com/WebDollar/argon2-gpu
- Local checkout (gitignored): `research/third_party/argon2-gpu/`
- Consumed by research CUDA bench sources under `research/code/antech-kdf-research/src/compute_memory_v4/cuda/`

### Clone (optional)

```bash
git clone https://github.com/WebDollar/argon2-gpu.git research/third_party/argon2-gpu
cd research/third_party/argon2-gpu
git submodule update --init
# then build with CMake / CUDA per upstream README
```

Do **not** place this under the repo-root `third_party/` or under `crates/`.
