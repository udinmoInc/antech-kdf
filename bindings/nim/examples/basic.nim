import ../antech_kdf

let stored = hash("correct_horse_battery_staple")
doAssert verify("correct_horse_battery_staple", stored)

var cfg = configDefault()
cfg.memoryKib = 1024
let custom = hashWithConfig("pw", cfg)
echo "needs_rehash ", needsRehash(custom)
echo stored
