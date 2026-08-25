// Real CUDA Argon2id attacker bench — matches research baseline m=65536 KiB, t=2, p=1.
// Uses argon2-gpu (WebDollar) CUDA backend; static single-binary build.

#include "argon2-cuda/globalcontext.h"
#include "argon2-cuda/programcontext.h"
#include "argon2-cuda/processingunit.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cuda_runtime.h>

static const char ATTACKER_SALT[] = "v4_attacker_salt_16";
static const char CORRECT_SALT[] = "v4_gpu_correct_salt";
static const size_t HASH_LEN = 32;
static const size_t M_COST = 65536; // KiB
static const size_t T_COST = 2;
static const size_t LANES = 1;

static std::string hex32(const uint8_t* d) {
    static const char* h = "0123456789abcdef";
    std::string s(64, '0');
    for (int i = 0; i < 32; i++) {
        s[2 * i] = h[d[i] >> 4];
        s[2 * i + 1] = h[d[i] & 0xf];
    }
    return s;
}

static std::vector<std::string> attacker_corpus() {
    std::vector<std::string> v;
    v.reserve(256);
    for (int i = 0; i < 256; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "v4_attacker_candidate_%04d", i);
        v.push_back(buf);
    }
    return v;
}

struct BenchResult {
    double gps = 0;
    double kernel_p50_ms = 0, kernel_p95_ms = 0, kernel_p99_ms = 0;
    double host_device_ms = 0;
    size_t batch = 0;
    float occupancy = 0;
    int regs = 0;
    size_t vram_used_mib = 0;
};

static double pct(std::vector<double>& v, double p) {
    std::sort(v.begin(), v.end());
    if (v.empty()) return 0;
    size_t i = (size_t)std::round((v.size() - 1) * p);
    return v[std::min(i, v.size() - 1)];
}

static BenchResult run_batch(
    argon2::cuda::ProcessingUnit& unit,
    const std::vector<std::string>& passwords,
    bool profile
) {
    BenchResult br;
    br.batch = passwords.size();
    auto t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < passwords.size(); i++) {
        unit.setPassword(i, passwords[i].data(), passwords[i].size());
    }
    auto t1 = std::chrono::steady_clock::now();

    cudaEvent_t ev0, ev1;
    cudaEventCreate(&ev0);
    cudaEventCreate(&ev1);

    std::vector<double> kms;
    const int iters = profile ? 5 : 1;
    for (int it = 0; it < iters; it++) {
        cudaEventRecord(ev0);
        unit.beginProcessing();
        unit.endProcessing();
        cudaEventRecord(ev1);
        cudaEventSynchronize(ev1);
        float ms = 0;
        cudaEventElapsedTime(&ms, ev0, ev1);
        kms.push_back(ms);
    }
    auto t2 = std::chrono::steady_clock::now();

    std::vector<uint8_t> hashes(passwords.size() * HASH_LEN);
    for (size_t i = 0; i < passwords.size(); i++) {
        unit.getHash(i, hashes.data() + i * HASH_LEN);
    }
    auto t3 = std::chrono::steady_clock::now();

    double avg_k = 0;
    for (double x : kms) avg_k += x;
    avg_k /= kms.size();
    br.gps = (avg_k > 0) ? (passwords.size() * 1000.0 / avg_k) : 0;
    br.kernel_p50_ms = pct(kms, 0.50);
    br.kernel_p95_ms = pct(kms, 0.95);
    br.kernel_p99_ms = pct(kms, 0.99);
    br.host_device_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count() +
        std::chrono::duration<double, std::milli>(t3 - t2).count();

    size_t free_b = 0, total_b = 0;
    cudaMemGetInfo(&free_b, &total_b);
    br.vram_used_mib = (total_b - free_b) / (1024 * 1024);

    cudaEventDestroy(ev0);
    cudaEventDestroy(ev1);
    (void)t2;
    return br;
}

static int pick_batch_size() {
    size_t free_b = 0, total_b = 0;
    cudaMemGetInfo(&free_b, &total_b);
    // ~64 MiB per lane + overhead
    size_t per = (size_t)M_COST * 1024 + 256 * 1024;
    size_t budget = free_b > (size_t)512 * 1024 * 1024 ? free_b - (size_t)512 * 1024 * 1024 : free_b / 2;
    int batch = (int)(budget / per);
    if (batch < 1) batch = 1;
    if (batch > 96) batch = 96;
    return batch;
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "bench";
    std::string out_dir = (argc > 2) ? argv[2] : "research/results/compute-memory-v4/gpu";

    using namespace argon2::cuda;
    GlobalContext global;
    auto& devices = global.getAllDevices();
    if (devices.empty()) {
        fprintf(stderr, "No CUDA devices\n");
        return 1;
    }
    const Device& dev = devices[0];
    printf("GPU: %s\n", dev.getInfo().c_str());

    ProgramContext pc(&global, {dev}, argon2::ARGON2_ID, argon2::ARGON2_VERSION_13);

    const char* salt = (mode == "correctness") ? CORRECT_SALT : ATTACKER_SALT;
    size_t salt_len = strlen(salt);

    if (mode == "correctness") {
        std::vector<std::string> pws;
        for (int i = 0; i < 10; i++) {
            char buf[64];
            snprintf(buf, sizeof(buf), "argon2_gpu_vector_%02d", i);
            pws.push_back(buf);
        }
        argon2::Argon2Params params(
            HASH_LEN, salt, salt_len, nullptr, 0, nullptr, 0,
            T_COST, M_COST, LANES);
        ProcessingUnit unit(&pc, &params, &dev, pws.size(), true, false);
        BenchResult br = run_batch(unit, pws, false);

        std::ofstream out(out_dir + "/argon2_cuda_digests.txt");
        for (size_t i = 0; i < pws.size(); i++) {
            uint8_t h[32];
            unit.getHash(i, h);
            out << pws[i] << " " << hex32(h) << "\n";
            printf("GPU[%zu] %s %s\n", i, pws[i].c_str(), hex32(h).c_str());
        }
        (void)br;
        return 0;
    }

    // bench
    int batch = pick_batch_size();
    printf("Argon2id batch=%d (m=%zu KiB t=%zu p=%zu)\n", batch, M_COST, T_COST, LANES);

    argon2::Argon2Params params(
        HASH_LEN, salt, salt_len, nullptr, 0, nullptr, 0,
        T_COST, M_COST, LANES);
    ProcessingUnit unit(&pc, &params, &dev, (size_t)batch, true, false);

    auto corpus = attacker_corpus();
    std::vector<std::string> batch_pws;
    for (int i = 0; i < batch; i++) batch_pws.push_back(corpus[i % corpus.size()]);

    BenchResult br = run_batch(unit, batch_pws, true);
    printf("GPS=%.4f k_p50=%.2f ms VRAM=%zu MiB H<->D=%.2f ms\n",
           br.gps, br.kernel_p50_ms, br.vram_used_mib, br.host_device_ms);

    std::ofstream pf(out_dir + "/argon2_gpu_raw.txt");
    pf << "guesses_per_sec=" << br.gps << "\n"
       << "kernel_p50_ms=" << br.kernel_p50_ms << "\n"
       << "kernel_p95_ms=" << br.kernel_p95_ms << "\n"
       << "kernel_p99_ms=" << br.kernel_p99_ms << "\n"
       << "vram_used_mib=" << br.vram_used_mib << "\n"
       << "host_device_transfer_ms=" << br.host_device_ms << "\n"
       << "batch=" << br.batch << "\n"
       << "m_cost_kib=" << M_COST << "\n"
       << "t_cost=" << T_COST << "\n"
       << "lanes=" << LANES << "\n";
    return 0;
}
