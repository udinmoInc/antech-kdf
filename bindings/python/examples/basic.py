import antech_kdf

stored = antech_kdf.hash("correct_horse_battery_staple")
assert antech_kdf.verify("correct_horse_battery_staple", stored)

cfg = antech_kdf.Config.default()
cfg.memory_kib = 1024
custom = antech_kdf.hash_with_config("pw", cfg)
print("needs_rehash", antech_kdf.needs_rehash(custom))

pol = antech_kdf.RehashPolicy.default()
pol.preferred_memory_kib = 32768
print("policy", antech_kdf.needs_rehash_with_policy(custom, pol))
print(stored)
