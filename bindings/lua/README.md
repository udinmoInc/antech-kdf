# Antech KDF — Lua (LuaJIT)

Thin FFI wrapper. Requires **LuaJIT** (`require("ffi")`).

```bash
./sdk/scripts/build-native.sh
luajit bindings/lua/examples/basic.lua
```

```lua
local antech = require("antech_kdf")
local stored = antech.hash("correct_horse_battery_staple")
assert(antech.verify("correct_horse_battery_staple", stored))
```

Optional secret / associated data: `nil` = absent; `""` = present-but-empty.
