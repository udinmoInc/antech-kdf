# GPU final note (superseded)

Early GPU attempts on this host failed when `nvcc` could not find `cl.exe`, so those campaigns correctly recorded **CUDA UNAVAILABLE**.

Later runs with a working toolchain are under [compute-memory-v4/gpu/report.md](../compute-memory-v4/gpu/report.md): Antech v4-C ~33 g/s vs Argon2id ~436 g/s on RTX 3050 at 16 MiB (`MEASURED`).
