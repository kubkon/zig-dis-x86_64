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

    const exe = b.addExecutable(.{
        .name = "dis_x86_64",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = mode,
    });
    exe.addAnonymousModule("dis_x86_64", .{ .source_file = .{ .path = "src/dis_x86_64.zig" } });
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
