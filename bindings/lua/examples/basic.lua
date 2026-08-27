#!/usr/bin/env luajit
-- Requires LuaJIT (ffi). From repo root:
--   luajit bindings/lua/examples/basic.lua

package.path = package.path .. ";bindings/lua/?.lua;../?.lua"
local antech = require("antech_kdf")

local stored = antech.hash("correct_horse_battery_staple")
assert(antech.verify("correct_horse_battery_staple", stored))

local cfg = antech.config_default()
cfg.memory_kib = 1024
local custom = antech.hash_with_config("pw", cfg)
print("needs_rehash", antech.needs_rehash(custom))
print(stored)
