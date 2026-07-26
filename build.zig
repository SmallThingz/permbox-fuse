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
    const trie_logging_options = b.addOptions();
    trie_logging_options.addOption([]const u8, "module_name", "permbox.trie");
    const fuse_logging_options = b.addOptions();
    fuse_logging_options.addOption([]const u8, "module_name", "permbox.fuse");

    const trie_module = b.addModule("permtrie", .{
        .root_source_file = b.path("src/trie/root.zig"),
        .target = compile_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "logging_options", .module = trie_logging_options.createModule() },
        },
    });

    const permbox_module = b.addModule("permfuse", .{
        .root_source_file = b.path("src/fuse/root.zig"),
        .target = compile_target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "permtrie", .module = trie_module },
            .{ .name = "logging_options", .module = fuse_logging_options.createModule() },
        },
    });
    permbox_module.link_libc = true;
    permbox_module.addIncludePath(b.path("src"));
    permbox_module.addIncludePath(.{ .cwd_relative = "/usr/include/fuse3" });
    permbox_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    permbox_module.linkSystemLibrary("fuse3", .{});

    const cli = b.addExecutable(.{
        .name = "permfuse",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "permfuse", .module = permbox_module },
            },
        }),
        .use_llvm = true,
    });
    b.installArtifact(cli);

    // Keep the manual harness as an additional non-installed integration
    // target.
    const mount_test = b.addExecutable(.{
        .name = "permfuse-mount-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mount_test.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "permfuse", .module = permbox_module },
            },
        }),
    });

    const mount_test_step = b.step(
        "mount-test",
        "Build the non-installed manual mount integration harness",
    );
    mount_test_step.dependOn(&mount_test.step);

    const run_mount_test_step = b.step(
        "run-mount-test",
        "Run the manual mount integration harness",
    );
    const run_cmd = b.addRunArtifact(mount_test);
    if (b.args) |args| run_cmd.addArgs(args);
    run_mount_test_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    const test_runner: std.Build.Step.Compile.TestRunner = .{
        .path = b.path("src/test_runner.zig"),
        .mode = .simple,
    };
    const trie_tests = b.addTest(.{
        .root_module = trie_module,
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(trie_tests).step);

    const policy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuse/policy.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{.{ .name = "permtrie", .module = trie_module }},
        }),
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(policy_tests).step);

    const options_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuse/options.zig"),
            .target = compile_target,
            .optimize = optimize,
        }),
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(options_tests).step);

    const fs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuse/fs.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "permtrie", .module = trie_module },
                .{ .name = "logging_options", .module = fuse_logging_options.createModule() },
            },
        }),
        .test_runner = test_runner,
    });
    fs_tests.root_module.link_libc = true;
    fs_tests.root_module.addIncludePath(b.path("src"));
    fs_tests.root_module.addIncludePath(.{ .cwd_relative = "/usr/include/fuse3" });
    fs_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
    fs_tests.root_module.linkSystemLibrary("fuse3", .{});
    test_step.dependOn(&b.addRunArtifact(fs_tests).step);

    const overlay_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuse/overlay.zig"),
            .target = compile_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "logging_options", .module = fuse_logging_options.createModule() },
            },
        }),
        .test_runner = test_runner,
    });
    overlay_tests.root_module.link_libc = true;
    test_step.dependOn(&b.addRunArtifact(overlay_tests).step);

    const api_tests = b.addTest(.{
        .root_module = permbox_module,
        .test_runner = test_runner,
    });
    test_step.dependOn(&b.addRunArtifact(api_tests).step);
}
