const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("antech_kdf", .{
        .root_source_file = b.path("src/antech_kdf.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addIncludePath(b.path("../c"));

    const exe = b.addExecutable(.{
        .name = "antech-basic",
        .root_source_file = b.path("examples/basic.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("antech_kdf", mod);
    exe.addIncludePath(b.path("../c"));
    exe.addLibraryPath(b.path("../../sdk/native"));
    exe.addLibraryPath(b.path("../../target/release"));
    exe.linkSystemLibrary("antech_kdf");
    exe.linkLibC();
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run basic example");
    run_step.dependOn(&run.step);
}
