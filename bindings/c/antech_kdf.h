/**
 * Antech KDF C API Header
 *
 * Minimal C ABI header for Antech KDF.
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
    ANTECH_INTERNAL_ERROR = -3
} AntechStatus;

/**
 * Hashes password string into heap-allocated encoded hash.
 * Free string with antech_free().
 */
AntechStatus antech_hash(const char* password, char** out_hash);

/**
 * Verifies password against stored hash string.
 */
AntechStatus antech_verify(const char* password, const char* encoded_hash);

/**
 * Checks if stored hash string requires rehashing.
 */
AntechStatus antech_needs_rehash(const char* encoded_hash, int* out_needs_rehash);

/**
 * Frees string allocated by antech_hash.
 */
void antech_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* ANTECH_KDF_H */
