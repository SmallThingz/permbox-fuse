const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const logging_options = b.addOptions();
    logging_options.addOption([]const u8, "module_name", "permtrie");

    const mod = b.addModule("permtrie", .{
        .root_source_file = b.path("src/trie/trie.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "logging_options", .module = logging_options.createModule() },
        },
    });

    const exe = b.addExecutable(.{
        .name = "permbox-fuse",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "permtrie", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    const test_runner: std.Build.Step.Compile.TestRunner = .{
        .path = b.path("src/test_runner.zig"),
        .mode = .simple,
    };
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .root_module = mod,
        .test_runner = test_runner,
    })).step);
}
