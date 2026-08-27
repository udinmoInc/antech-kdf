# frozen_string_literal: true

require_relative "../lib/antech_kdf"

stored = Antech.hash("correct_horse_battery_staple")
raise "verify failed" unless Antech.verify("correct_horse_battery_staple", stored)

cfg = Antech::Config.default
cfg.memory_kib = 1024
custom = Antech.hash_with_config("pw", cfg)
puts "needs_rehash #{Antech.needs_rehash(custom)}"
puts stored
