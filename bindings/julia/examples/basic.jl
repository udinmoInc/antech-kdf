include(joinpath(@__DIR__, "..", "src", "AntechKdf.jl"))
using .AntechKdf

stored = AntechKdf.hash("correct_horse_battery_staple")
@assert AntechKdf.verify("correct_horse_battery_staple", stored)

cfg = AntechKdf.config_default()
cfg = AntechKdf.Config(UInt32(1024), cfg.salt_length, cfg.block_size, cfg.fan_in, cfg.graph, cfg.output_length)
custom = AntechKdf.hash_with_config("pw", cfg)
println("needs_rehash ", AntechKdf.needs_rehash(custom))
println(stored)
