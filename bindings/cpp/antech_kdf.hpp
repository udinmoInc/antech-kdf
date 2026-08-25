#pragma once
/**
 * Antech KDF — C++ wrapper (header-only) over the C ABI.
 * Thread-safe. Does not own cryptographic logic.
 */

#include "../c/antech_kdf.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace antech {

inline void check(AntechStatus st) {
  if (st == ANTECH_OK || st == ANTECH_VERIFICATION_FAILED) return;
  switch (st) {
    case ANTECH_INVALID_INPUT: throw std::invalid_argument("antech: invalid input");
    case ANTECH_INVALID_HASH: throw std::invalid_argument("antech: invalid hash");
    case ANTECH_INVALID_CONFIG: throw std::invalid_argument("antech: invalid config");
    default: throw std::runtime_error("antech: internal error");
  }
}

inline std::string take_string(char* p) {
  if (!p) throw std::runtime_error("antech: null string");
  std::string s(p);
  antech_free(p);
  return s;
}

inline AntechConfig default_config() {
  AntechConfig c{};
  check(antech_config_default(&c));
  return c;
}

inline AntechRehashPolicy default_rehash_policy() {
  AntechRehashPolicy p{};
  check(antech_rehash_policy_default(&p));
  return p;
}

inline std::string hash(std::string_view password) {
  char* out = nullptr;
  check(antech_hash_bytes(
      reinterpret_cast<const uint8_t*>(password.data()), password.size(), &out));
  return take_string(out);
}

inline std::string hash_with_config(std::string_view password, const AntechConfig& config) {
  char* out = nullptr;
  check(antech_hash_with_config_bytes(
      reinterpret_cast<const uint8_t*>(password.data()),
      password.size(),
      &config,
      &out));
  return take_string(out);
}

inline std::string hash_with_config_and_salt(
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt,
    const AntechConfig& config) {
  char* out = nullptr;
  check(antech_hash_with_config_and_salt(
      password.data(), password.size(), salt.data(), salt.size(), &config, &out));
  return take_string(out);
}

inline bool verify(std::string_view password, std::string_view encoded_hash) {
  std::string hash_nul(encoded_hash);
  AntechStatus st = antech_verify_bytes(
      reinterpret_cast<const uint8_t*>(password.data()),
      password.size(),
      hash_nul.c_str());
  if (st == ANTECH_OK) return true;
  if (st == ANTECH_VERIFICATION_FAILED) return false;
  check(st);
  return false;
}

inline bool needs_rehash(std::string_view encoded_hash) {
  std::string h(encoded_hash);
  int out = 0;
  check(antech_needs_rehash(h.c_str(), &out));
  return out != 0;
}

inline bool needs_rehash_with_policy(
    std::string_view encoded_hash,
    const AntechRehashPolicy& policy) {
  std::string h(encoded_hash);
  int out = 0;
  check(antech_needs_rehash_with_policy(h.c_str(), &policy, &out));
  return out != 0;
}

inline const char* version() { return antech_version(); }

}  // namespace antech
