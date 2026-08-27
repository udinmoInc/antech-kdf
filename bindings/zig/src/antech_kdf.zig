//! Thin Zig wrapper over bindings/c/antech_kdf.h
pub const package_version = "0.1.0";

const std = @import("std");
const c = @cImport({
    @cInclude("antech_kdf.h");
});

pub const Error = error{
    InvalidInput,
    InvalidHash,
    InvalidConfig,
    Internal,
    NullString,
    Library,
};

pub const Config = struct {
    memory_kib: u32 = 16384,
    salt_length: u32 = 16,
    block_size: u32 = 32,
    fan_in: u32 = 2,
    graph: u32 = 3,
    output_length: u32 = 32,

    pub fn toC(self: Config) c.AntechConfig {
        return .{
            .memory_kib = self.memory_kib,
            .salt_length = self.salt_length,
            .block_size = self.block_size,
            .fan_in = self.fan_in,
            .graph = self.graph,
            .output_length = self.output_length,
        };
    }

    pub fn default() Error!Config {
        var cfg: c.AntechConfig = undefined;
        try raise(c.antech_config_default(&cfg));
        return .{
            .memory_kib = cfg.memory_kib,
            .salt_length = cfg.salt_length,
            .block_size = cfg.block_size,
            .fan_in = cfg.fan_in,
            .graph = cfg.graph,
            .output_length = cfg.output_length,
        };
    }
};

fn raise(st: c.AntechStatus) Error!void {
    switch (st) {
        c.ANTECH_OK => {},
        c.ANTECH_INVALID_INPUT => return error.InvalidInput,
        c.ANTECH_INVALID_HASH => return error.InvalidHash,
        c.ANTECH_INVALID_CONFIG => return error.InvalidConfig,
        else => return error.Internal,
    }
}

fn take(allocator: std.mem.Allocator, ptr: ?[*:0]u8) Error![]u8 {
    const p = ptr orelse return error.NullString;
    const slice = std.mem.span(p);
    const owned = try allocator.dupe(u8, slice);
    c.antech_free(p);
    return owned;
}

pub fn version() [:0]const u8 {
    const v = c.antech_version();
    if (v == null) return package_version;
    return std.mem.span(v);
}

pub fn hash(allocator: std.mem.Allocator, password: []const u8) Error![]u8 {
    var out: ?[*:0]u8 = null;
    try raise(c.antech_hash_bytes(password.ptr, password.len, &out));
    return take(allocator, out);
}

pub fn hashWithConfig(allocator: std.mem.Allocator, password: []const u8, config: Config) Error![]u8 {
    var cfg = config.toC();
    var out: ?[*:0]u8 = null;
    try raise(c.antech_hash_with_config_bytes(password.ptr, password.len, &cfg, &out));
    return take(allocator, out);
}

pub fn verify(password: []const u8, encoded_hash: [:0]const u8) Error!bool {
    const st = c.antech_verify_bytes(password.ptr, password.len, encoded_hash.ptr);
    if (st == c.ANTECH_OK) return true;
    if (st == c.ANTECH_VERIFICATION_FAILED) return false;
    try raise(st);
    return false;
}

pub fn needsRehash(encoded_hash: [:0]const u8) Error!bool {
    var needs: c_int = 0;
    try raise(c.antech_needs_rehash(encoded_hash.ptr, &needs));
    return needs != 0;
}
