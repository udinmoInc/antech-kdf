// v4c_gpu_attacker.cu — REAL CUDA attacker for Antech compute-memory v4-C @ 16 MiB
// Exact structural walk matching crates/.../compute_memory_v4 (CombinedFrontier).
// Seed bind + finalize use host SHA-256 (identical domains); memory-hard DAG on device.
// Does NOT modify the CPU KDF implementation.

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cuda_runtime.h>

// ---- protocol constants (must match Rust v4-C) ----
static const uint32_t V4_VERSION = 4;
static const uint32_t GRAPH_TAG_C = 3;
static const uint32_t MIX_ROUNDS = 4;
static const uint32_t BLOCK_SIZE = 32;
static const uint32_t FAN_IN = 2;
static const uint32_t MEMORY_MIB = 16;
static const uint32_t MEMORY_KIB = MEMORY_MIB * 1024;
static const uint32_t NUM_BLOCKS = (MEMORY_KIB * 1024u) / BLOCK_SIZE; // 524288
static const uint32_t FRONTIER_WIDTH = 64;
static const uint32_t TILE_BLOCKS = 512;
static const uint32_t CRITICAL_PERIOD = 4; // FRONTIER_WIDTH/16
static const uint32_t TILE_LEN = 512;      // min(TILE_BLOCKS, NUM_BLOCKS)

static const uint64_t C1 = 0xBF58476D1CE4E5B9ULL;
static const uint64_t C2 = 0x94D049BB133111EBULL;
static const uint64_t GOLDEN = 0x9E3779B97F4A7C15ULL;

static const char DOMAIN_SEED[] = "antech-compute-memory-v4-seed";
static const char DOMAIN_FINAL[] = "antech-compute-memory-v4-final";
static const char DOMAIN_NODE0[] = "antech-compute-memory-v2-node0";

#define CUDA_CHECK(call)                                                         \
    do {                                                                         \
        cudaError_t _e = (call);                                                 \
        if (_e != cudaSuccess) {                                                 \
            fprintf(stderr, "CUDA error %s:%d: %s\n", __FILE__, __LINE__,        \
                    cudaGetErrorString(_e));                                     \
            exit(1);                                                             \
        }                                                                        \
    } while (0)

// ======================== Host SHA-256 ========================
struct Sha256Ctx {
    uint64_t bitlen;
    uint32_t state[8];
    uint8_t data[64];
    uint32_t datalen;
};

static uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(Sha256Ctx* ctx, const uint8_t data[]) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t m[64], a,b,c,d,e,f,g,h,t1,t2;
    for (uint32_t i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for (uint32_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(m[i-15],7) ^ rotr32(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = rotr32(m[i-2],17) ^ rotr32(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + m[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(Sha256Ctx* ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256Ctx* ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8ull;
    ctx->data[63] = (uint8_t)ctx->bitlen;
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    Sha256Ctx ctx; sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, out);
}

static void put_u32_le(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void put_u64_le(uint8_t* p, uint64_t v) {
    for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i));
}

static void bind_seed_v4(const uint8_t* pw, uint32_t pw_len, const uint8_t* salt, uint32_t salt_len,
                         uint8_t seed[32]) {
    // Match Rust bind_seed_v4 field order exactly.
    std::vector<uint8_t> buf;
    auto append = [&](const void* p, size_t n) {
        const uint8_t* b = (const uint8_t*)p;
        buf.insert(buf.end(), b, b + n);
    };
    append(DOMAIN_SEED, sizeof(DOMAIN_SEED) - 1);
    uint8_t tmp[4];
    put_u32_le(tmp, V4_VERSION); append(tmp, 4);
    put_u32_le(tmp, GRAPH_TAG_C); append(tmp, 4);
    put_u32_le(tmp, pw_len); append(tmp, 4);
    append(pw, pw_len);
    put_u32_le(tmp, salt_len); append(tmp, 4);
    append(salt, salt_len);
    put_u32_le(tmp, MEMORY_KIB); append(tmp, 4);
    put_u32_le(tmp, BLOCK_SIZE); append(tmp, 4);
    put_u32_le(tmp, FAN_IN); append(tmp, 4);
    put_u32_le(tmp, MIX_ROUNDS); append(tmp, 4);
    put_u32_le(tmp, CRITICAL_PERIOD); append(tmp, 4);
    put_u32_le(tmp, TILE_LEN); append(tmp, 4);
    sha256(buf.data(), buf.size(), seed);
}

static void phantom_block(const uint8_t seed[32], uint32_t slot, uint8_t out[32]) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), DOMAIN_NODE0, DOMAIN_NODE0 + sizeof(DOMAIN_NODE0) - 1);
    buf.insert(buf.end(), seed, seed + 32);
    uint8_t sl[4]; put_u32_le(sl, slot);
    buf.insert(buf.end(), sl, sl + 4);
    sha256(buf.data(), buf.size(), out);
}

static void finalize_v4(const uint8_t seed[32], const uint64_t state[4], const uint8_t last[32],
                        uint8_t digest[32]) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), DOMAIN_FINAL, DOMAIN_FINAL + sizeof(DOMAIN_FINAL) - 1);
    uint8_t tmp[8];
    put_u32_le(tmp, V4_VERSION); buf.insert(buf.end(), tmp, tmp + 4);
    put_u32_le(tmp, GRAPH_TAG_C); buf.insert(buf.end(), tmp, tmp + 4);
    buf.insert(buf.end(), seed, seed + 32);
    for (int i = 0; i < 4; i++) { put_u64_le(tmp, state[i]); buf.insert(buf.end(), tmp, tmp + 8); }
    buf.insert(buf.end(), last, last + 32);
    sha256(buf.data(), buf.size(), digest);
}

// ======================== Device helpers ========================
__device__ __forceinline__ uint64_t d_rotl(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}
__device__ __forceinline__ uint64_t d_load_u64(const uint8_t* p) {
    uint64_t v = 0;
#pragma unroll
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
__device__ __forceinline__ void d_store_u64(uint8_t* p, uint64_t v) {
#pragma unroll
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

__device__ void d_mix_pair(uint64_t s[4], const uint8_t* b1, const uint8_t* b2) {
    uint64_t b10 = d_load_u64(b1), b11 = d_load_u64(b1+8), b12 = d_load_u64(b1+16), b13 = d_load_u64(b1+24);
    uint64_t b20 = d_load_u64(b2), b21 = d_load_u64(b2+8), b22 = d_load_u64(b2+16), b23 = d_load_u64(b2+24);
#pragma unroll
    for (uint32_t r = 0; r < MIX_ROUNDS; r++) {
        uint64_t rr = r;
        s[0] = d_rotl(s[0] + (b10 ^ (b20 + rr)), 13) ^ s[3];
        s[1] = d_rotl(s[1] + ((b11 * C1) ^ b21), 17) ^ s[0];
        s[2] = d_rotl(s[2] + (b12 ^ (b22 * C2)), 19) ^ s[1];
        s[3] = d_rotl(s[3] + ((b13 + b23) ^ (GOLDEN * (rr + 1))), 23) ^ s[2];
    }
}

__device__ void d_state_to_block(const uint64_t s[4], uint8_t out[32]) {
#pragma unroll
    for (int i = 0; i < 4; i++) d_store_u64(out + i * 8, s[i]);
}

__device__ void d_xor_state(const uint64_t s[4], uint8_t* block) {
#pragma unroll
    for (int i = 0; i < 4; i++) {
        uint8_t bytes[8]; d_store_u64(bytes, s[i]);
#pragma unroll
        for (int j = 0; j < 8; j++) block[i * 8 + j] ^= bytes[j];
    }
}

struct DParents {
    uint32_t indices[8];
    uint32_t len;
    int scatter1; // -1 if none
    int scatter2;
};

__device__ void d_push_unique(DParents* p, uint32_t addr, uint32_t i) {
    if (addr >= i || p->len >= 8) return;
    for (uint32_t j = 0; j < p->len; j++) if (p->indices[j] == addr) return;
    p->indices[p->len++] = addr;
}

__device__ void d_local_frontier(DParents* out, const uint64_t state[4], uint32_t i, uint32_t fan_in) {
    d_push_unique(out, i - 1, i);
    uint32_t fw = FRONTIER_WIDTH < i ? FRONTIER_WIDTH : i;
    uint32_t slot = (uint32_t)(state[0] % fw);
    d_push_unique(out, i - 1 - slot, i);
    uint32_t guard = 0;
    while (out->len < fan_in && guard < fan_in + 4) {
        guard++;
        uint64_t mix = state[out->len % 4] ^ ((uint64_t)i * GOLDEN);
        slot = (uint32_t)(mix % fw);
        uint32_t before = out->len;
        d_push_unique(out, i - 1 - slot, i);
        if (out->len == before) {
            uint32_t slot2 = (uint32_t)((state[2] + guard) % fw);
            d_push_unique(out, i - 1 - slot2, i);
            if (out->len == before) break;
        }
    }
}

// CombinedFrontier parent selection (exact port of graph.rs::combined)
__device__ DParents d_parents_combined(const uint64_t state[4], uint32_t i) {
    DParents out;
    out.len = 0; out.scatter1 = -1; out.scatter2 = -1;
    if (i == 0) return out;

    uint32_t tile = TILE_LEN > FRONTIER_WIDTH ? TILE_LEN : FRONTIER_WIDTH;
    // tile = tile_len.max(TILE_BLOCKS.min(512)) with tile_len=512 → 512
    tile = TILE_LEN;
    if (tile < 512) { /* keep */ }
    // In Rust: tile_len.max(TILE_BLOCKS.min(512)) = 512.max(512.min(512)) = 512
    uint32_t tile_start = (i / tile) * tile;
    int critical = ((CRITICAL_PERIOD > 0) && (i % CRITICAL_PERIOD == 0)) ||
                   (i > 0 && (i % FRONTIER_WIDTH == 0));

    d_local_frontier(&out, state, i, 2);

    if (i > tile_start + 1) {
        uint32_t span = i - tile_start;
        uint32_t local_remote = tile_start + (uint32_t)(state[1] % span);
        d_push_unique(&out, local_remote, i);
    }

    uint32_t fw = FRONTIER_WIDTH < i ? FRONTIER_WIDTH : i;
    if (i > fw + 1) {
        uint32_t remote_span = i - fw;
        if (critical || ((i & 1u) == 0u)) {
            uint32_t far = (uint32_t)((state[1] ^ d_rotl(state[3], 11)) % remote_span);
            d_push_unique(&out, far, i);
        }
        if (critical) {
            uint32_t far2 = (uint32_t)((state[0] ^ GOLDEN) % remote_span);
            d_push_unique(&out, far2, i);
        }
    }

    uint32_t guard = 0;
    while (out.len < FAN_IN && guard < 4) {
        guard++;
        uint64_t mix = state[out.len % 4] ^ ((uint64_t)i * GOLDEN);
        uint32_t before = out.len;
        uint32_t addr;
        if (i > tile_start) {
            uint32_t den = (i - tile_start);
            if (den == 0) den = 1;
            addr = tile_start + (uint32_t)(mix % den);
        } else {
            addr = (uint32_t)(mix % i);
        }
        d_push_unique(&out, addr, i);
        if (out.len == before) break;
    }

    if (i > fw) {
        uint32_t span = i - fw;
        out.scatter1 = (int)((state[2] ^ GOLDEN) % span);
        out.scatter2 = (int)((state[3] ^ d_rotl(state[0], 7)) % span);
    }
    return out;
}

struct FrontierRing {
    uint8_t data[FRONTIER_WIDTH * BLOCK_SIZE];
    int newest; // -1 empty
    uint32_t count;
};

__device__ void ring_init(FrontierRing* r) { r->newest = -1; r->count = 0; }

__device__ void ring_push(FrontierRing* r, uint32_t idx, const uint8_t* block) {
    uint32_t slot = idx % FRONTIER_WIDTH;
    memcpy(&r->data[slot * BLOCK_SIZE], block, BLOCK_SIZE);
    r->newest = (int)idx;
    r->count = r->count + 1 < FRONTIER_WIDTH ? r->count + 1 : FRONTIER_WIDTH;
}

__device__ const uint8_t* ring_get(const FrontierRing* r, uint32_t idx) {
    if (r->newest < 0) return nullptr;
    if ((int)idx > r->newest) return nullptr;
    uint32_t age = (uint32_t)r->newest - idx;
    uint32_t window = r->count < FRONTIER_WIDTH ? r->count : FRONTIER_WIDTH;
    if (age >= window) return nullptr;
    return &r->data[(idx % FRONTIER_WIDTH) * BLOCK_SIZE];
}

// One full v4-C derive walk. buffer is NUM_BLOCKS*32 bytes, zeroed by caller.
__device__ void v4c_walk(const uint8_t seed[32], const uint8_t phantoms[2][32],
                         uint8_t* buffer, uint64_t state_out[4], uint8_t last_out[32]) {
    uint64_t state[4];
#pragma unroll
    for (int i = 0; i < 4; i++) state[i] = d_load_u64(seed + i * 8);

    FrontierRing ring;
    ring_init(&ring);

    for (uint32_t i = 0; i < NUM_BLOCKS; i++) {
        DParents parents = d_parents_combined(state, i);
        const uint8_t* views[8];
        uint32_t n_views = 0;
        if (i == 0) {
            views[0] = phantoms[0];
            views[1] = phantoms[1];
            n_views = FAN_IN;
        } else {
            for (uint32_t k = 0; k < parents.len; k++) {
                uint32_t p = parents.indices[k];
                const uint8_t* v = ring_get(&ring, p);
                views[n_views++] = v ? v : (buffer + (size_t)p * BLOCK_SIZE);
            }
        }
        if (n_views == 1) {
            d_mix_pair(state, views[0], views[0]);
        } else {
            uint32_t vi = 0;
            while (vi + 1 < n_views) {
                d_mix_pair(state, views[vi], views[vi + 1]);
                vi += 2;
            }
            if (vi < n_views) d_mix_pair(state, views[vi], views[vi]);
        }

        uint8_t* out = buffer + (size_t)i * BLOCK_SIZE;
        d_state_to_block(state, out);
        ring_push(&ring, i, out);

        if (parents.scatter1 >= 0) {
            uint32_t dest = (uint32_t)parents.scatter1;
            if (dest < NUM_BLOCKS && dest != i) d_xor_state(state, buffer + (size_t)dest * BLOCK_SIZE);
        }
        if (parents.scatter2 >= 0) {
            uint32_t dest = (uint32_t)parents.scatter2;
            if (dest < NUM_BLOCKS && dest != i) d_xor_state(state, buffer + (size_t)dest * BLOCK_SIZE);
        }
    }

#pragma unroll
    for (int i = 0; i < 4; i++) state_out[i] = state[i];
    memcpy(last_out, buffer + (size_t)(NUM_BLOCKS - 1) * BLOCK_SIZE, BLOCK_SIZE);
}

__global__ void v4c_guess_kernel(
    const uint8_t* seeds,          // n * 32
    const uint8_t* phantoms,       // n * 2 * 32
    uint8_t* buffers,              // n * NUM_BLOCKS * 32
    uint64_t* states_out,          // n * 4
    uint8_t* lasts_out,            // n * 32
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    const uint8_t* seed = seeds + (size_t)idx * 32;
    const uint8_t* ph = phantoms + (size_t)idx * 2 * 32;
    uint8_t ph_local[2][32];
    memcpy(ph_local[0], ph, 32);
    memcpy(ph_local[1], ph + 32, 32);

    uint8_t* buffer = buffers + (size_t)idx * (size_t)NUM_BLOCKS * BLOCK_SIZE;
    // buffer assumed zeroed by host cudaMemset

    uint64_t st[4];
    uint8_t last[32];
    v4c_walk(seed, ph_local, buffer, st, last);

#pragma unroll
    for (int i = 0; i < 4; i++) states_out[(size_t)idx * 4 + i] = st[i];
    memcpy(lasts_out + (size_t)idx * 32, last, 32);
}

__global__ void v4c_guess_kernel_fused_zero(
    const uint8_t* seeds,
    const uint8_t* phantoms,
    uint8_t* buffers,
    uint64_t* states_out,
    uint8_t* lasts_out,
    int n
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    uint8_t* buffer = buffers + (size_t)idx * (size_t)NUM_BLOCKS * BLOCK_SIZE;
    for (size_t off = 0; off < (size_t)NUM_BLOCKS * BLOCK_SIZE; off += 32) {
        ((uint4*)(buffer + off))[0] = make_uint4(0, 0, 0, 0);
        ((uint4*)(buffer + off))[1] = make_uint4(0, 0, 0, 0);
    }
    const uint8_t* seed = seeds + (size_t)idx * 32;
    const uint8_t* ph = phantoms + (size_t)idx * 2 * 32;
    uint8_t ph_local[2][32];
    memcpy(ph_local[0], ph, 32);
    memcpy(ph_local[1], ph + 32, 32);
    uint64_t st[4];
    uint8_t last[32];
    v4c_walk(seed, ph_local, buffer, st, last);
#pragma unroll
    for (int i = 0; i < 4; i++) states_out[(size_t)idx * 4 + i] = st[i];
    memcpy(lasts_out + (size_t)idx * 32, last, 32);
}

// ---- Packed u64 attacker (same graph; word loads; optional ring; no memset) ----
__device__ __forceinline__ void d_mix_words(uint64_t s[4], const uint64_t a[4], const uint64_t b[4]) {
#pragma unroll
    for (uint32_t r = 0; r < MIX_ROUNDS; r++) {
        uint64_t rr = r;
        s[0] = d_rotl(s[0] + (a[0] ^ (b[0] + rr)), 13) ^ s[3];
        s[1] = d_rotl(s[1] + ((a[1] * C1) ^ b[1]), 17) ^ s[0];
        s[2] = d_rotl(s[2] + (a[2] ^ (b[2] * C2)), 19) ^ s[1];
        s[3] = d_rotl(s[3] + ((a[3] + b[3]) ^ (GOLDEN * (rr + 1))), 23) ^ s[2];
    }
}

__device__ __forceinline__ void d_push_u(uint32_t* idx, uint32_t* len, uint32_t addr, uint32_t i) {
    if (addr >= i || *len >= 8) return;
#pragma unroll
    for (uint32_t j = 0; j < 8; j++) {
        if (j < *len && idx[j] == addr) return;
    }
    idx[(*len)++] = addr;
}

__device__ DParents d_parents_combined_fast(const uint64_t state[4], uint32_t i) {
    DParents out;
    out.len = 0; out.scatter1 = -1; out.scatter2 = -1;
    if (i == 0) return out;
    uint32_t tile = TILE_LEN;
    uint32_t tile_start = (i / tile) * tile;
    int critical = ((i % CRITICAL_PERIOD) == 0) || ((i % FRONTIER_WIDTH) == 0);

    d_push_u(out.indices, &out.len, i - 1, i);
    uint32_t fw = FRONTIER_WIDTH < i ? FRONTIER_WIDTH : i;
    d_push_u(out.indices, &out.len, i - 1 - (uint32_t)(state[0] % fw), i);
    uint32_t guard = 0;
    while (out.len < 2 && guard < 6) {
        guard++;
        uint64_t mix = state[out.len % 4] ^ ((uint64_t)i * GOLDEN);
        uint32_t before = out.len;
        d_push_u(out.indices, &out.len, i - 1 - (uint32_t)(mix % fw), i);
        if (out.len == before) {
            d_push_u(out.indices, &out.len, i - 1 - (uint32_t)((state[2] + guard) % fw), i);
            if (out.len == before) break;
        }
    }
    if (i > tile_start + 1) {
        uint32_t span = i - tile_start;
        d_push_u(out.indices, &out.len, tile_start + (uint32_t)(state[1] % span), i);
    }
    if (i > fw + 1) {
        uint32_t remote_span = i - fw;
        if (critical || ((i & 1u) == 0u)) {
            d_push_u(out.indices, &out.len,
                     (uint32_t)((state[1] ^ d_rotl(state[3], 11)) % remote_span), i);
        }
        if (critical) {
            d_push_u(out.indices, &out.len, (uint32_t)((state[0] ^ GOLDEN) % remote_span), i);
        }
    }
    guard = 0;
    while (out.len < FAN_IN && guard < 4) {
        guard++;
        uint64_t mix = state[out.len % 4] ^ ((uint64_t)i * GOLDEN);
        uint32_t before = out.len;
        uint32_t addr = (i > tile_start)
            ? tile_start + (uint32_t)(mix % ((i - tile_start) ? (i - tile_start) : 1))
            : (uint32_t)(mix % i);
        d_push_u(out.indices, &out.len, addr, i);
        if (out.len == before) break;
    }
    if (i > fw) {
        uint32_t span = i - fw;
        out.scatter1 = (int)((state[2] ^ GOLDEN) % span);
        out.scatter2 = (int)((state[3] ^ d_rotl(state[0], 7)) % span);
    }
    return out;
}

__device__ void v4c_walk_packed(const uint8_t seed[32], const uint64_t phantoms[2][4],
                                uint64_t* buf, uint64_t state_out[4], uint64_t last_out[4],
                                int use_ring) {
    uint64_t state[4];
#pragma unroll
    for (int i = 0; i < 4; i++) state[i] = d_load_u64(seed + i * 8);

    uint64_t ring[FRONTIER_WIDTH][4];
    int newest = -1;
    uint32_t count = 0;

    for (uint32_t i = 0; i < NUM_BLOCKS; i++) {
        DParents parents = d_parents_combined_fast(state, i);
        uint64_t views[8][4];
        uint32_t n_views = 0;
        if (i == 0) {
#pragma unroll
            for (int w = 0; w < 4; w++) {
                views[0][w] = phantoms[0][w];
                views[1][w] = phantoms[1][w];
            }
            n_views = FAN_IN;
        } else {
            for (uint32_t k = 0; k < parents.len; k++) {
                uint32_t p = parents.indices[k];
                int from_ring = 0;
                if (use_ring && newest >= 0 && (int)p <= newest) {
                    uint32_t age = (uint32_t)newest - p;
                    uint32_t window = count < FRONTIER_WIDTH ? count : FRONTIER_WIDTH;
                    if (age < window) {
#pragma unroll
                        for (int w = 0; w < 4; w++) views[n_views][w] = ring[p % FRONTIER_WIDTH][w];
                        from_ring = 1;
                    }
                }
                if (!from_ring) {
                    uint64_t* src = buf + (size_t)p * 4;
#pragma unroll
                    for (int w = 0; w < 4; w++) views[n_views][w] = src[w];
                }
                n_views++;
            }
        }
        if (n_views == 1) {
            d_mix_words(state, views[0], views[0]);
        } else {
            uint32_t vi = 0;
            while (vi + 1 < n_views) {
                d_mix_words(state, views[vi], views[vi + 1]);
                vi += 2;
            }
            if (vi < n_views) d_mix_words(state, views[vi], views[vi]);
        }
        uint64_t* out = buf + (size_t)i * 4;
#pragma unroll
        for (int w = 0; w < 4; w++) out[w] = state[w];
        if (use_ring) {
#pragma unroll
            for (int w = 0; w < 4; w++) ring[i % FRONTIER_WIDTH][w] = state[w];
            newest = (int)i;
            count = count + 1 < FRONTIER_WIDTH ? count + 1 : FRONTIER_WIDTH;
        }
        if (parents.scatter1 >= 0) {
            uint32_t dest = (uint32_t)parents.scatter1;
            if (dest < NUM_BLOCKS && dest != i) {
                uint64_t* d = buf + (size_t)dest * 4;
#pragma unroll
                for (int w = 0; w < 4; w++) d[w] ^= state[w];
            }
        }
        if (parents.scatter2 >= 0) {
            uint32_t dest = (uint32_t)parents.scatter2;
            if (dest < NUM_BLOCKS && dest != i) {
                uint64_t* d = buf + (size_t)dest * 4;
#pragma unroll
                for (int w = 0; w < 4; w++) d[w] ^= state[w];
            }
        }
    }
#pragma unroll
    for (int i = 0; i < 4; i++) {
        state_out[i] = state[i];
        last_out[i] = buf[(size_t)(NUM_BLOCKS - 1) * 4 + i];
    }
}

enum KernelKind { K_BASELINE = 0, K_FUSED = 1, K_PACKED = 2, K_PACKED_NORING = 3, K_PACKED_PERSIST = 4 };

__global__ void v4c_guess_kernel_packed(
    const uint8_t* seeds, const uint8_t* phantoms, uint64_t* buffers,
    uint64_t* states_out, uint8_t* lasts_out, int n, int use_ring
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    const uint8_t* seed = seeds + (size_t)idx * 32;
    const uint8_t* ph = phantoms + (size_t)idx * 64;
    uint64_t phw[2][4];
#pragma unroll
    for (int s = 0; s < 2; s++)
#pragma unroll
        for (int w = 0; w < 4; w++) phw[s][w] = d_load_u64(ph + s * 32 + w * 8);
    uint64_t* buffer = buffers + (size_t)idx * (size_t)NUM_BLOCKS * 4;
    uint64_t st[4], last[4];
    v4c_walk_packed(seed, phw, buffer, st, last, use_ring);
#pragma unroll
    for (int i = 0; i < 4; i++) states_out[(size_t)idx * 4 + i] = st[i];
#pragma unroll
    for (int i = 0; i < 4; i++) d_store_u64(lasts_out + (size_t)idx * 32 + i * 8, last[i]);
}

__global__ void v4c_guess_kernel_packed_persist(
    const uint8_t* seeds, const uint8_t* phantoms, uint64_t* buffers,
    uint64_t* states_out, uint8_t* lasts_out, int n, int n_slots
) {
    int slot = blockIdx.x * blockDim.x + threadIdx.x;
    if (slot >= n_slots) return;
    uint64_t* buffer = buffers + (size_t)slot * (size_t)NUM_BLOCKS * 4;
    for (int idx = slot; idx < n; idx += n_slots) {
        const uint8_t* seed = seeds + (size_t)idx * 32;
        const uint8_t* ph = phantoms + (size_t)idx * 64;
        uint64_t phw[2][4];
#pragma unroll
        for (int s = 0; s < 2; s++)
#pragma unroll
            for (int w = 0; w < 4; w++) phw[s][w] = d_load_u64(ph + s * 32 + w * 8);
        uint64_t st[4], last[4];
        v4c_walk_packed(seed, phw, buffer, st, last, 0);
#pragma unroll
        for (int i = 0; i < 4; i++) states_out[(size_t)idx * 4 + i] = st[i];
#pragma unroll
        for (int i = 0; i < 4; i++) d_store_u64(lasts_out + (size_t)idx * 32 + i * 8, last[i]);
    }
}

static std::string hex32(const uint8_t* d) {
    static const char* hexd = "0123456789abcdef";
    std::string s(64, '0');
    for (int i = 0; i < 32; i++) {
        s[2*i] = hexd[d[i] >> 4];
        s[2*i+1] = hexd[d[i] & 0xf];
    }
    return s;
}

static bool parse_hex32(const std::string& h, uint8_t out[32]) {
    if (h.size() != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < 32; i++) {
        int a = nibble(h[2*i]), b = nibble(h[2*i+1]);
        if (a < 0 || b < 0) return false;
        out[i] = (uint8_t)((a << 4) | b);
    }
    return true;
}

struct GpuProfile {
    double guesses_per_sec = 0;
    double kernel_p50_ms = 0, kernel_p95_ms = 0, kernel_p99_ms = 0;
    double host_device_ms = 0, kernel_exec_ms_total = 0;
    size_t vram_used_bytes = 0;
    int batch = 0;
    int regs_per_thread = 0;
    size_t shared_mem = 0;
    float occupancy = 0;
    size_t global_traffic_est = 0;
    int threads_per_block = 1;
    size_t spill_store_bytes = 0;
    size_t spill_load_bytes = 0;
};

struct LaunchConfig {
    int threads = 1;
    bool fused_zero = false;
    bool pinned_host = false;
    bool async_copy = false;
    KernelKind kind = K_BASELINE;
    int force_batch = 0;
    int persist_slots = 0;
};

static double percentile(std::vector<double>& v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)std::round((v.size() - 1) * p);
    if (idx >= v.size()) idx = v.size() - 1;
    return v[idx];
}

static void prepare_batch(const std::vector<std::string>& pws, const uint8_t* salt, uint32_t salt_len,
                          std::vector<uint8_t>& seeds, std::vector<uint8_t>& phantoms) {
    int n = (int)pws.size();
    seeds.assign((size_t)n * 32, 0);
    phantoms.assign((size_t)n * 2 * 32, 0);
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        bind_seed_v4((const uint8_t*)pws[i].data(), (uint32_t)pws[i].size(), salt, salt_len, seed);
        memcpy(seeds.data() + (size_t)i * 32, seed, 32);
        phantom_block(seed, 0, phantoms.data() + (size_t)i * 64);
        phantom_block(seed, 1, phantoms.data() + (size_t)i * 64 + 32);
    }
}

static void run_gpu_batch(const std::vector<uint8_t>& seeds, const std::vector<uint8_t>& phantoms,
                          std::vector<uint8_t>& digests, GpuProfile* prof, bool profile_kernels,
                          const LaunchConfig& cfg) {
    int n = (int)(seeds.size() / 32);
    digests.assign((size_t)n * 32, 0);

    bool packed = cfg.kind == K_PACKED || cfg.kind == K_PACKED_NORING || cfg.kind == K_PACKED_PERSIST;
    size_t words_per = (size_t)NUM_BLOCKS * 4;
    size_t buf_bytes = packed ? ((size_t)n * words_per * sizeof(uint64_t))
                              : ((size_t)n * (size_t)NUM_BLOCKS * BLOCK_SIZE);
    int persist_slots = cfg.persist_slots > 0 ? cfg.persist_slots : n;
    if (cfg.kind == K_PACKED_PERSIST) {
        buf_bytes = (size_t)persist_slots * words_per * sizeof(uint64_t);
    }

    uint8_t *d_seeds=nullptr, *d_ph=nullptr, *d_last=nullptr;
    uint64_t *d_state=nullptr;
    uint8_t *d_buf8=nullptr;
    uint64_t *d_buf64=nullptr;

    auto t_h0 = std::chrono::steady_clock::now();
    cudaStream_t stream = nullptr;
    if (cfg.async_copy) CUDA_CHECK(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking));
    CUDA_CHECK(cudaMalloc(&d_seeds, seeds.size()));
    CUDA_CHECK(cudaMalloc(&d_ph, phantoms.size()));
    if (packed) CUDA_CHECK(cudaMalloc(&d_buf64, buf_bytes));
    else CUDA_CHECK(cudaMalloc(&d_buf8, buf_bytes));
    CUDA_CHECK(cudaMalloc(&d_state, (size_t)n * 4 * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_last, (size_t)n * 32));
    const uint8_t* h_seeds = seeds.data();
    const uint8_t* h_ph = phantoms.data();
    uint8_t* pinned_seeds = nullptr;
    uint8_t* pinned_ph = nullptr;
    if (cfg.pinned_host) {
        CUDA_CHECK(cudaMallocHost(&pinned_seeds, seeds.size()));
        CUDA_CHECK(cudaMallocHost(&pinned_ph, phantoms.size()));
        memcpy(pinned_seeds, seeds.data(), seeds.size());
        memcpy(pinned_ph, phantoms.data(), phantoms.size());
        h_seeds = pinned_seeds;
        h_ph = pinned_ph;
    }
    if (cfg.async_copy) {
        CUDA_CHECK(cudaMemcpyAsync(d_seeds, h_seeds, seeds.size(), cudaMemcpyHostToDevice, stream));
        CUDA_CHECK(cudaMemcpyAsync(d_ph, h_ph, phantoms.size(), cudaMemcpyHostToDevice, stream));
    } else {
        CUDA_CHECK(cudaMemcpy(d_seeds, h_seeds, seeds.size(), cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(d_ph, h_ph, phantoms.size(), cudaMemcpyHostToDevice));
    }
    // Packed walks overwrite every block before read; no memset required.
    if (!packed && !cfg.fused_zero) {
        if (cfg.async_copy) CUDA_CHECK(cudaMemsetAsync(d_buf8, 0, buf_bytes, stream));
        else CUDA_CHECK(cudaMemset(d_buf8, 0, buf_bytes));
    }
    if (cfg.async_copy) CUDA_CHECK(cudaStreamSynchronize(stream));
    auto t_h1 = std::chrono::steady_clock::now();
    double h2d = std::chrono::duration<double, std::milli>(t_h1 - t_h0).count();

    int threads = cfg.threads;
    int launch_n = (cfg.kind == K_PACKED_PERSIST) ? persist_slots : n;
    int blocks = (launch_n + threads - 1) / threads;

    int regs = 0; size_t smem = 0;
    cudaFuncAttributes attr;
    if (packed) {
        if (cudaFuncGetAttributes(&attr, v4c_guess_kernel_packed) == cudaSuccess) {
            regs = attr.numRegs; smem = attr.sharedSizeBytes;
        }
    } else if (cudaFuncGetAttributes(&attr, v4c_guess_kernel) == cudaSuccess) {
        regs = attr.numRegs; smem = attr.sharedSizeBytes;
    }
    int maxBlocks = 0;
    if (cfg.kind == K_PACKED || cfg.kind == K_PACKED_NORING) {
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxBlocks, v4c_guess_kernel_packed, threads, 0);
    } else if (cfg.kind == K_PACKED_PERSIST) {
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxBlocks, v4c_guess_kernel_packed_persist, threads, 0);
    } else if (cfg.fused_zero) {
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxBlocks, v4c_guess_kernel_fused_zero, threads, 0);
    } else {
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxBlocks, v4c_guess_kernel, threads, 0);
    }
    cudaDeviceProp prop; cudaGetDeviceProperties(&prop, 0);
    float occ = 0;
    if (prop.multiProcessorCount > 0 && prop.maxThreadsPerMultiProcessor > 0) {
        occ = (float)(maxBlocks * threads) / (float)prop.maxThreadsPerMultiProcessor;
    }
    cudaFuncSetCacheConfig(v4c_guess_kernel_packed, cudaFuncCachePreferL1);

    std::vector<double> kms;
    cudaEvent_t ev0, ev1;
    CUDA_CHECK(cudaEventCreate(&ev0));
    CUDA_CHECK(cudaEventCreate(&ev1));

    auto launch = [&]() {
        if (cfg.kind == K_PACKED) {
            v4c_guess_kernel_packed<<<blocks, threads>>>(d_seeds, d_ph, d_buf64, d_state, d_last, n, 1);
        } else if (cfg.kind == K_PACKED_NORING) {
            v4c_guess_kernel_packed<<<blocks, threads>>>(d_seeds, d_ph, d_buf64, d_state, d_last, n, 0);
        } else if (cfg.kind == K_PACKED_PERSIST) {
            v4c_guess_kernel_packed_persist<<<blocks, threads>>>(
                d_seeds, d_ph, d_buf64, d_state, d_last, n, persist_slots);
        } else if (cfg.fused_zero) {
            v4c_guess_kernel_fused_zero<<<blocks, threads>>>(d_seeds, d_ph, d_buf8, d_state, d_last, n);
        } else {
            v4c_guess_kernel<<<blocks, threads>>>(d_seeds, d_ph, d_buf8, d_state, d_last, n);
        }
    };

    launch();
    CUDA_CHECK(cudaDeviceSynchronize());
    if (!packed && !cfg.fused_zero) CUDA_CHECK(cudaMemset(d_buf8, 0, buf_bytes));

    auto wall0 = std::chrono::steady_clock::now();
    const int iters = profile_kernels ? 5 : 1;
    float ksum = 0;
    for (int it = 0; it < iters; it++) {
        if (!packed && !cfg.fused_zero) CUDA_CHECK(cudaMemset(d_buf8, 0, buf_bytes));
        CUDA_CHECK(cudaEventRecord(ev0));
        launch();
        CUDA_CHECK(cudaEventRecord(ev1));
        CUDA_CHECK(cudaEventSynchronize(ev1));
        float ms = 0;
        CUDA_CHECK(cudaEventElapsedTime(&ms, ev0, ev1));
        kms.push_back(ms);
        ksum += ms;
    }
    auto wall1 = std::chrono::steady_clock::now();
    double wall_ms = std::chrono::duration<double, std::milli>(wall1 - wall0).count();

    std::vector<uint64_t> states((size_t)n * 4);
    std::vector<uint8_t> lasts((size_t)n * 32);
    auto t_d0 = std::chrono::steady_clock::now();
    CUDA_CHECK(cudaMemcpy(states.data(), d_state, states.size() * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(lasts.data(), d_last, lasts.size(), cudaMemcpyDeviceToHost));
    auto t_d1 = std::chrono::steady_clock::now();
    double d2h = std::chrono::duration<double, std::milli>(t_d1 - t_d0).count();

    for (int i = 0; i < n; i++) {
        uint8_t digest[32];
        finalize_v4(seeds.data() + (size_t)i * 32,
                    states.data() + (size_t)i * 4,
                    lasts.data() + (size_t)i * 32, digest);
        memcpy(digests.data() + (size_t)i * 32, digest, 32);
    }

    size_t free_b=0, total_b=0;
    cudaMemGetInfo(&free_b, &total_b);

    if (prof) {
        double avg_k = ksum / iters;
        prof->guesses_per_sec = (avg_k > 0) ? (n * 1000.0 / avg_k) : 0;
        prof->kernel_p50_ms = percentile(kms, 0.50);
        prof->kernel_p95_ms = percentile(kms, 0.95);
        prof->kernel_p99_ms = percentile(kms, 0.99);
        prof->host_device_ms = h2d + d2h;
        prof->kernel_exec_ms_total = ksum;
        prof->vram_used_bytes = total_b - free_b;
        prof->batch = n;
        prof->regs_per_thread = regs;
        prof->shared_mem = smem;
        prof->occupancy = occ;
        prof->threads_per_block = threads;
        prof->global_traffic_est = (size_t)n * (size_t)NUM_BLOCKS * (size_t)(3 + 2) * BLOCK_SIZE;
        (void)wall_ms;
    }

    CUDA_CHECK(cudaEventDestroy(ev0));
    CUDA_CHECK(cudaEventDestroy(ev1));
    if (pinned_seeds) CUDA_CHECK(cudaFreeHost(pinned_seeds));
    if (pinned_ph) CUDA_CHECK(cudaFreeHost(pinned_ph));
    if (stream) CUDA_CHECK(cudaStreamDestroy(stream));
    cudaFree(d_seeds); cudaFree(d_ph); cudaFree(d_state); cudaFree(d_last);
    if (d_buf8) cudaFree(d_buf8);
    if (d_buf64) cudaFree(d_buf64);
}

static std::vector<std::string> attacker_corpus() {
    std::vector<std::string> v;
    v.reserve(256);
    for (int i = 0; i < 256; i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "v4_attacker_candidate_%04d", i);
        v.emplace_back(buf);
    }
    return v;
}

static LaunchConfig cfg_for_mode(const std::string& mode) {
    LaunchConfig cfg;
    if (mode == "baseline") {
        cfg.threads = 1;
        cfg.kind = K_BASELINE;
    } else if (mode == "optimized") {
        cfg.threads = 32;
        cfg.pinned_host = true;
        cfg.async_copy = true;
        cfg.kind = K_BASELINE;
    } else if (mode == "fully_optimized") {
        cfg.threads = 128;
        cfg.pinned_host = true;
        cfg.async_copy = true;
        cfg.fused_zero = true;
        cfg.kind = K_FUSED;
    } else if (mode == "packed") {
        cfg.threads = 32;
        cfg.pinned_host = true;
        cfg.async_copy = true;
        cfg.kind = K_PACKED;
        cfg.force_batch = 192;
    } else if (mode == "packed_noring") {
        cfg.threads = 32;
        cfg.pinned_host = true;
        cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING;
        cfg.force_batch = 192;
    } else if (mode == "packed_persistent") {
        cfg.threads = 32;
        cfg.pinned_host = true;
        cfg.async_copy = true;
        cfg.kind = K_PACKED_PERSIST;
        cfg.force_batch = 256;
        cfg.persist_slots = 96;
    } else if (mode == "packed_t8_b128") {
        cfg.threads = 8; cfg.pinned_host = true; cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING; cfg.force_batch = 128;
    } else if (mode == "packed_t16_b192") {
        cfg.threads = 16; cfg.pinned_host = true; cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING; cfg.force_batch = 192;
    } else if (mode == "packed_t32_b192") {
        cfg.threads = 32; cfg.pinned_host = true; cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING; cfg.force_batch = 192;
    } else if (mode == "packed_t32_b256") {
        cfg.threads = 32; cfg.pinned_host = true; cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING; cfg.force_batch = 256;
    } else if (mode == "packed_t64_b128") {
        cfg.threads = 64; cfg.pinned_host = true; cfg.async_copy = true;
        cfg.kind = K_PACKED_NORING; cfg.force_batch = 128;
    } else {
        cfg.threads = 1;
        cfg.kind = K_BASELINE;
    }
    return cfg;
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "bench";
    std::string out_dir = (argc > 2) ? argv[2] : "research/results/compute-memory-v4/gpu";
    std::string impl_mode = (argc > 3) ? argv[3] : "baseline";
    int correctness_count = (argc > 4) ? atoi(argv[4]) : 10;
    LaunchConfig launch = cfg_for_mode(impl_mode);

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    printf("GPU: %s | VRAM=%zu MiB | SMs=%d | CC=%d.%d\n",
           prop.name, prop.totalGlobalMem / (1024*1024), prop.multiProcessorCount,
           prop.major, prop.minor);

    const uint8_t salt[] = "v4_attacker_salt_16"; // 19 bytes? Rust is b"v4_attacker_salt_16" = 19 chars
    // Actually: b"v4_attacker_salt_16" length = 19
    uint32_t salt_len = (uint32_t)strlen((const char*)salt);

    if (mode == "correctness") {
        std::vector<std::string> pws;
        for (int i = 0; i < correctness_count; i++) {
            char buf[64];
            snprintf(buf, sizeof(buf), "v4c_gpu_vector_%02d", i);
            pws.emplace_back(buf);
        }
        // Use dedicated correctness salt matching Rust harness
        const uint8_t csalt[] = "v4_gpu_correct_salt"; // 19 bytes
        uint32_t cslen = (uint32_t)strlen((const char*)csalt);

        std::vector<uint8_t> seeds, ph, digests;
        prepare_batch(pws, csalt, cslen, seeds, ph);
        GpuProfile prof{};
        run_gpu_batch(seeds, ph, digests, &prof, false, launch);

        // Write GPU digests
        std::ofstream out(out_dir + "/cuda_digests.txt");
        for (int i = 0; i < correctness_count; i++) {
            out << pws[i] << " " << hex32(digests.data() + (size_t)i * 32) << "\n";
            printf("GPU[%d] %s %s\n", i, pws[i].c_str(), hex32(digests.data() + i*32).c_str());
        }
        out.close();

        // If CPU reference file exists, compare
        std::ifstream ref(out_dir + "/cpu_digests.txt");
        int mismatches = 0;
        if (ref) {
            for (int i = 0; i < correctness_count; i++) {
                std::string pw, hex;
                ref >> pw >> hex;
                uint8_t expect[32];
                if (!parse_hex32(hex, expect)) { printf("bad ref hex\n"); return 2; }
                if (memcmp(expect, digests.data() + (size_t)i * 32, 32) != 0) {
                    printf("MISMATCH vector %d\n  CPU %s\n  GPU %s\n", i, hex.c_str(),
                           hex32(digests.data()+i*32).c_str());
                    mismatches++;
                } else {
                    printf("MATCH vector %d\n", i);
                }
            }
            if (mismatches) {
                printf("CORRECTNESS FAILED: %d mismatches\n", mismatches);
                return 3;
            }
            printf("CORRECTNESS OK: %d/%d\n", correctness_count, correctness_count);
        } else {
            printf("No cpu_digests.txt yet — wrote cuda_digests.txt for host compare.\n");
        }
        return 0;
    }

    // Bench mode: same corpus as CPU attacker
    auto corpus = attacker_corpus();
    // Choose batch by VRAM: leave ~1.5 GiB free
    size_t free_b=0, total_b=0;
    CUDA_CHECK(cudaMemGetInfo(&free_b, &total_b));
    size_t per = (size_t)NUM_BLOCKS * BLOCK_SIZE + 65536;
    int max_batch = (int)((free_b > (size_t)1536*1024*1024 ? free_b - (size_t)1536*1024*1024 : free_b / 2) / per);
    if (max_batch < 1) max_batch = 1;
    if (max_batch > 256) max_batch = 256; // VRAM-limited concurrency of full 16 MiB walks
    int batch = max_batch;
    if (launch.force_batch > 0) {
        batch = launch.force_batch;
        if (batch > max_batch) batch = max_batch;
    } else if (impl_mode == "baseline") {
        if (batch > 64) batch = 64;
    } else if (impl_mode == "optimized") {
        if (batch >= 192) batch = 192;
        else if (batch >= 128) batch = 128;
        else if (batch >= 96) batch = 96;
    } else {
        if (batch >= 256) batch = 256;
        else if (batch >= 192) batch = 192;
        else if (batch >= 128) batch = 128;
    }
    printf("Selected batch=%d (%.2f MiB buffers)\n", batch,
           (batch * (double)NUM_BLOCKS * BLOCK_SIZE) / (1024.0*1024.0));

    // Build a batch of passwords cycling the corpus
    std::vector<std::string> batch_pws;
    for (int i = 0; i < batch; i++) batch_pws.push_back(corpus[i % (int)corpus.size()]);

    std::vector<uint8_t> seeds, ph, digests;
    prepare_batch(batch_pws, salt, salt_len, seeds, ph);
    GpuProfile prof{};
    run_gpu_batch(seeds, ph, digests, &prof, true, launch);

    printf("[%s] GPS=%.4f  k_p50=%.3f ms  k_p95=%.3f  k_p99=%.3f\n",
           impl_mode.c_str(),
           prof.guesses_per_sec, prof.kernel_p50_ms, prof.kernel_p95_ms, prof.kernel_p99_ms);
    printf("VRAM_used≈%zu MiB  occ=%.3f  regs=%d  smem=%zu  tpb=%d  H<->D=%.3f ms\n",
           prof.vram_used_bytes/(1024*1024), prof.occupancy, prof.regs_per_thread,
           prof.shared_mem, prof.threads_per_block, prof.host_device_ms);

    // Write machine-readable profile
    std::ofstream pf(out_dir + "/antech_gpu_raw_" + impl_mode + ".txt");
    pf << "guesses_per_sec=" << prof.guesses_per_sec << "\n"
       << "kernel_p50_ms=" << prof.kernel_p50_ms << "\n"
       << "kernel_p95_ms=" << prof.kernel_p95_ms << "\n"
       << "kernel_p99_ms=" << prof.kernel_p99_ms << "\n"
       << "vram_used_mib=" << (prof.vram_used_bytes/(1024*1024)) << "\n"
       << "occupancy=" << prof.occupancy << "\n"
       << "registers_per_thread=" << prof.regs_per_thread << "\n"
       << "shared_mem_bytes=" << prof.shared_mem << "\n"
       << "threads_per_block=" << prof.threads_per_block << "\n"
       << "global_mem_traffic_est=" << prof.global_traffic_est << "\n"
       << "host_device_transfer_ms=" << prof.host_device_ms << "\n"
       << "kernel_exec_ms_total=" << prof.kernel_exec_ms_total << "\n"
       << "batch=" << prof.batch << "\n"
       << "impl_mode=" << impl_mode << "\n"
       << "gpu_name=" << prop.name << "\n"
       << "vram_total_mib=" << (prop.totalGlobalMem/(1024*1024)) << "\n";
    pf.close();
    return 0;
}
