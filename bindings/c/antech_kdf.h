/**
 * Antech KDF — C ABI
 * Package: antech-kdf 0.1.0 — Udinmo, Inc. <antech-kdf@udinmo.com>
 *
 * Thin FFI over the canonical Rust implementation. Do not reimplement crypto here.
 *
 * Ownership: strings from hash helpers must be freed with antech_free().
 * Thread safety: all entry points are thread-safe and stateless.
 * Platforms: Windows / Linux / macOS (cdylib); mobile via cargo-ndk / XCFramework builds.
 *
 * Optional secret / associated data (antech_*_with_inputs*):
 *   - pointer NULL and length 0  → input absent
 *   - non-NULL pointer, length 0 → present but empty (distinct from absent)
 *   - non-NULL pointer, length N → present with N bytes
 *   - NULL with length > 0       → ANTECH_INVALID_INPUT
 *
 * Secret bytes are never stored in the encoded hash. Associated data is not stored
 * either; only public markers sk=1 / adl=n appear when those inputs were used.
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
    /** Non-zero: prefer hashes that record sk=1. Does not compare secret bytes. */
    uint32_t preferred_secret_required;
    /** Non-zero: prefer hashes that record an adl= requirement. */
    uint32_t preferred_associated_data;
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

AntechStatus antech_hash_with_inputs_bytes(
    const uint8_t* password,
    size_t password_len,
    const AntechConfig* config,
    const uint8_t* secret,
    size_t secret_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    char** out_hash
);

AntechStatus antech_hash_with_inputs_and_salt(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    const AntechConfig* config,
    const uint8_t* secret,
    size_t secret_len,
    const uint8_t* associated_data,
    size_t associated_data_len,
    char** out_hash
);

AntechStatus antech_verify(const char* password, const char* encoded_hash);
AntechStatus antech_verify_bytes(
    const uint8_t* password,
    size_t password_len,
    const char* encoded_hash
);

AntechStatus antech_verify_with_inputs_bytes(
    const uint8_t* password,
    size_t password_len,
    const char* encoded_hash,
    const uint8_t* secret,
    size_t secret_len,
    const uint8_t* associated_data,
    size_t associated_data_len
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
