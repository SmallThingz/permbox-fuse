const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // An explicit GNU target makes Zig use its compatible libc startup files.
    // Native GCC 16 crt objects currently contain .sframe relocations that the
    // Zig 0.16 linker cannot consume.
    const compile_target = if (target.query.isNative())
        b.resolveTargetQuery(.{
            .cpu_arch = target.result.cpu.arch,
            .os_tag = target.result.os.tag,
            .abi = target.result.abi,
            .glibc_version = target.result.os.versionRange().gnuLibCVersion(),
        })
    else
        target;
    const optimize = b.standardOptimizeOption(.{});
    const logging_options = b.addOptions();
    logging_options.addOption([]const u8, "module_name", "permtrie");

    const mod = b.addModule("permtrie", .{
        .root_source_file = b.path("src/trie/trie.zig"),
        .target = compile_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "logging_options", .module = logging_options.createModule() },
        },
    });

    const exe = b.addExecutable(.{
        .name = "permbox-fuse",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "permtrie", .module = mod },
            },
        }),
    });
    exe.root_module.link_libc = true;
    exe.root_module.addIncludePath(b.path("src"));
    exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    exe.root_module.linkSystemLibrary("fuse3", .{});
    exe.root_module.addCSourceFile(.{
        .file = b.path("src/fuse_shim.c"),
        .flags = &.{"-std=c11"},
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
    const trie_tests = b.addTest(.{
        .root_module = mod,
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(trie_tests).step);

    const policy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/policy.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "permtrie", .module = mod }},
        }),
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(policy_tests).step);

    const options_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/options.zig"),
            .target = compile_target,
            .optimize = optimize,
        }),
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(options_tests).step);

    const fs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fs.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "permtrie", .module = mod }},
        }),
        .test_runner = test_runner,
    });
    fs_tests.root_module.link_libc = true;
    fs_tests.root_module.addIncludePath(b.path("src"));
    fs_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    fs_tests.root_module.linkSystemLibrary("fuse3", .{});
    fs_tests.root_module.addCSourceFile(.{
        .file = b.path("src/fuse_shim.c"),
        .flags = &.{"-std=c11"},
    });
    test_step.dependOn(&b.addRunArtifact(fs_tests).step);
}
