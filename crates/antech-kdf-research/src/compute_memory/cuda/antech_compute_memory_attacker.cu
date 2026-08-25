// antech_compute_memory_attacker.cu — v2 structure-derived probe
// Work bound = memory_kib*1024/block_size nodes (no separate depth knob).

#include <cstdio>
#include <cstdint>
#include <cuda_runtime.h>
#include <chrono>
#include <vector>
#include <cstdlib>

__device__ void mix4(uint64_t s[4], const uint8_t* b1, const uint8_t* b2) {
    auto load = [](const uint8_t* p, int off) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)p[off + i] << (8 * i);
        return v;
    };
    uint64_t b10 = load(b1, 0), b11 = load(b1, 8), b12 = load(b1, 16), b13 = load(b1, 24);
    uint64_t b20 = load(b2, 0), b21 = load(b2, 8), b22 = load(b2, 16), b23 = load(b2, 24);
    const uint64_t C1 = 0xBF58476D1CE4E5B9ULL;
    const uint64_t C2 = 0x94D049BB133111EBULL;
    const uint64_t G  = 0x9E3779B97F4A7C15ULL;
    for (int r = 0; r < 4; r++) {
        uint64_t rr = (uint64_t)r;
        s[0] = ((s[0] + (b10 ^ (b20 + rr))) << 13 | (s[0] + (b10 ^ (b20 + rr))) >> (64-13)) ^ s[3];
        s[1] = ((s[1] + ((b11 * C1) ^ b21)) << 17 | (s[1] + ((b11 * C1) ^ b21)) >> (64-17)) ^ s[0];
        s[2] = ((s[2] + (b12 ^ (b22 * C2))) << 19 | (s[2] + (b12 ^ (b22 * C2))) >> (64-19)) ^ s[1];
        s[3] = ((s[3] + ((b13 + b23) ^ (G * (rr + 1)))) << 23 |
                (s[3] + ((b13 + b23) ^ (G * (rr + 1)))) >> (64-23)) ^ s[2];
    }
}

// Probe uses a reduced on-device window; full 12–32 MiB sets exceed practical
// per-thread local memory. Host OptimizedEngine remains the reference.
extern "C" __global__ void antech_cm_guess(
    const unsigned char* passwords,
    const unsigned char* salts,
    unsigned int memory_kib,
    unsigned char* digests,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    unsigned int num_blocks = (memory_kib * 1024u) / 32u;
    // Cap device probe walk to keep kernel runnable; still sequential/stateful.
    unsigned int walk = num_blocks < 4096u ? num_blocks : 4096u;

    const int LOCAL_BLOCKS = 256;
    uint8_t local[LOCAL_BLOCKS * 32];
    uint64_t state[4];
    for (int i = 0; i < 4; i++) {
        state[i] = ((uint64_t)passwords[(idx * 16 + i) % 16]) << 32
                 ^ ((uint64_t)salts[(idx * 16 + i) % 16])
                 ^ ((uint64_t)memory_kib << 16)
                 ^ (uint64_t)idx;
    }
    for (int i = 0; i < LOCAL_BLOCKS * 32; i++) {
        local[i] = (uint8_t)(state[i & 3] >> ((i & 7) * 8));
    }
    for (unsigned step = 0; step < walk; step++) {
        int p1 = (int)((step == 0) ? 0 : ((step - 1) % LOCAL_BLOCKS));
        int p2 = (int)(state[1] % LOCAL_BLOCKS);
        mix4(state, &local[p1 * 32], &local[p2 * 32]);
        int dest = (int)(step % LOCAL_BLOCKS);
        for (int j = 0; j < 32; j++) {
            local[dest * 32 + j] = (uint8_t)(state[j & 3] >> ((j & 7) * 8));
        }
    }
    for (int j = 0; j < 32; j++) {
        digests[idx * 32 + j] = (uint8_t)(state[j & 3] >> ((j & 7) * 8));
    }
}

int main(int argc, char** argv) {
    unsigned int memory_mib = 16;
    if (argc > 1) memory_mib = (unsigned)atoi(argv[1]);
    unsigned int memory_kib = memory_mib * 1024;
    const int n = 64;

    std::vector<unsigned char> passwords(n * 16, 0x41);
    std::vector<unsigned char> salts(n * 16, 0x42);
    std::vector<unsigned char> digests(n * 32, 0);

    unsigned char *d_pw = nullptr, *d_sa = nullptr, *d_dg = nullptr;
    cudaMalloc(&d_pw, passwords.size());
    cudaMalloc(&d_sa, salts.size());
    cudaMalloc(&d_dg, digests.size());
    cudaMemcpy(d_pw, passwords.data(), passwords.size(), cudaMemcpyHostToDevice);
    cudaMemcpy(d_sa, salts.data(), salts.size(), cudaMemcpyHostToDevice);

    int threads = 64;
    int blocks = (n + threads - 1) / threads;

    antech_cm_guess<<<blocks, threads>>>(d_pw, d_sa, memory_kib, d_dg, n);
    cudaDeviceSynchronize();

    auto t0 = std::chrono::steady_clock::now();
    const int iters = 8;
    for (int i = 0; i < iters; i++) {
        antech_cm_guess<<<blocks, threads>>>(d_pw, d_sa, memory_kib, d_dg, n);
    }
    cudaDeviceSynchronize();
    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();
    double gps = (n * iters) / (secs > 1e-9 ? secs : 1e-9);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "cuda error: %s\n", cudaGetErrorString(err));
        return 1;
    }

    printf("guesses_per_sec=%.4f\n", gps);
    printf("memory_mib=%u\n", memory_mib);
    printf("num_blocks=%u\n", (memory_kib * 1024u) / 32u);
    printf("batch=%d\n", n);

    cudaFree(d_pw); cudaFree(d_sa); cudaFree(d_dg);
    return 0;
}
