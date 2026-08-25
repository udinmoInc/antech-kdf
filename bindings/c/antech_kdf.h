/**
 * Antech KDF — C ABI
 *
 * Thin FFI over the canonical Rust implementation. Do not reimplement crypto here.
 *
 * Ownership: strings from hash helpers must be freed with antech_free().
 * Thread safety: all entry points are thread-safe and stateless.
 * Platforms: Windows / Linux / macOS (cdylib); mobile via cargo-ndk / XCFramework builds.
 */

#ifndef ANTECH_KDF_H
#define ANTECH_KDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum AntechStatus {
    ANTECH_OK = 0,
    ANTECH_VERIFICATION_FAILED = 1,
    ANTECH_INVALID_INPUT = -1,
    ANTECH_INVALID_HASH = -2,
    ANTECH_INTERNAL_ERROR = -3,
    ANTECH_INVALID_CONFIG = -4
} AntechStatus;

#define ANTECH_GRAPH_REDUCED_CRITICAL_PATH 1u
#define ANTECH_GRAPH_CACHE_LOCALITY 2u
#define ANTECH_GRAPH_COMBINED_FRONTIER 3u

typedef struct AntechConfig {
    uint32_t memory_kib;
    uint32_t salt_length;
    uint32_t block_size;
    uint32_t fan_in;
    uint32_t graph;
    uint32_t output_length;
} AntechConfig;

typedef struct AntechRehashPolicy {
    uint32_t minimum_memory_kib;
    uint32_t preferred_memory_kib;
    uint32_t preferred_fan_in;
    uint32_t preferred_output_length;
} AntechRehashPolicy;

const char* antech_version(void);

AntechStatus antech_config_default(AntechConfig* out);
AntechStatus antech_rehash_policy_default(AntechRehashPolicy* out);

AntechStatus antech_hash(const char* password, char** out_hash);
AntechStatus antech_hash_bytes(const uint8_t* password, size_t password_len, char** out_hash);

AntechStatus antech_hash_with_config(
    const char* password,
    const AntechConfig* config,
    char** out_hash
);
AntechStatus antech_hash_with_config_bytes(
    const uint8_t* password,
    size_t password_len,
    const AntechConfig* config,
    char** out_hash
);
AntechStatus antech_hash_with_config_and_salt(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    const AntechConfig* config,
    char** out_hash
);

AntechStatus antech_verify(const char* password, const char* encoded_hash);
AntechStatus antech_verify_bytes(
    const uint8_t* password,
    size_t password_len,
    const char* encoded_hash
);

AntechStatus antech_needs_rehash(const char* encoded_hash, int* out_needs_rehash);
AntechStatus antech_needs_rehash_with_policy(
    const char* encoded_hash,
    const AntechRehashPolicy* policy,
    int* out_needs_rehash
);

void antech_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* ANTECH_KDF_H */
