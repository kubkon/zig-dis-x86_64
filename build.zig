const std = @import("std");

pub fn build(b: *std.Build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    b.addModule(.{
        .name = "dis_x86_64",
        .source_file = .{ .path = "src/dis_x86_64.zig" },
    });

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/dis_x86_64.zig" },
        .target = target,
        .optimize = mode,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
