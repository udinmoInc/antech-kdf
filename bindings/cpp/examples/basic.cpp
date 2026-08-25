#include "antech_kdf.hpp"
#include <iostream>

int main() {
  auto stored = antech::hash("correct_horse_battery_staple");
  std::cout << stored << "\n";
  std::cout << std::boolalpha << antech::verify("correct_horse_battery_staple", stored) << "\n";
  auto cfg = antech::default_config();
  cfg.memory_kib = 1024;
  auto custom = antech::hash_with_config("pw", cfg);
  std::cout << "needs_rehash=" << antech::needs_rehash(custom) << "\n";
  auto pol = antech::default_rehash_policy();
  pol.preferred_memory_kib = 32768;
  std::cout << "policy=" << antech::needs_rehash_with_policy(custom, pol) << "\n";
}
