const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-dis-x86_64", "src/lib.zig");
    lib.setBuildMode(mode);
    lib.install();

    const lib_tests = b.addTest("src/lib.zig");
    lib_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    const exe = b.addExecutable("zig-dis-x86_64", "src/main.zig");
    exe.setBuildMode(mode);
    exe.addPackagePath("zig-dis-x86_64", "src/lib.zig");
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
