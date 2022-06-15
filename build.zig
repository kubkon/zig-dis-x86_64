const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("dis_x86_64", "src/dis_x86_64.zig");
    lib.setBuildMode(mode);
    lib.install();

    const lib_tests = b.addTest("src/dis_x86_64.zig");
    lib_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    const exe = b.addExecutable("dis_x86_64", "src/main.zig");
    exe.setBuildMode(mode);
    exe.addPackagePath("dis_x86_64", "src/dis_x86_64.zig");
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
