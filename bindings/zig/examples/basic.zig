const std = @import("std");
const antech = @import("antech_kdf");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stored = try antech.hash(allocator, "correct_horse_battery_staple");
    defer allocator.free(stored);
    const stored_z = try allocator.dupeZ(u8, stored);
    defer allocator.free(stored_z);

    if (!(try antech.verify("correct_horse_battery_staple", stored_z))) {
        return error.VerifyFailed;
    }

    var cfg = try antech.Config.default();
    cfg.memory_kib = 1024;
    const custom = try antech.hashWithConfig(allocator, "pw", cfg);
    defer allocator.free(custom);
    const custom_z = try allocator.dupeZ(u8, custom);
    defer allocator.free(custom_z);

    std.debug.print("needs_rehash {}\n", .{try antech.needsRehash(custom_z)});
    std.debug.print("{s}\n", .{stored});
}
