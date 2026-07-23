//! Test runner that reports library error logs without treating them as test
//! failures. Recoverable persistence/reclamation errors are part of the API's
//! fault model; assertions, returned errors, and leaks still fail the run.
const builtin = @import("builtin");
const std = @import("std");

pub const std_options: std.Options = .{
    .logFn = log,
};

pub fn getLogger(comptime module_name: []const u8) type {
    return struct {
        pub fn log(
            comptime level: std.log.Level,
            comptime format: []const u8,
            args: anytype,
        ) void {
            std.debug.print(level.asText() ++ "(" ++ module_name ++ "): " ++ format ++ "\n", args);
        }
    };
}

pub fn main(init: std.process.Init.Minimal) void {
    var passed: usize = 0;
    var skipped: usize = 0;
    var failed: usize = 0;
    var leaked: usize = 0;

    for (builtin.test_functions, 0..) |test_fn, index| {
        std.testing.allocator_instance = .{};
        std.testing.io_instance = .init(std.testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });
        std.testing.environ = init.environ;

        std.debug.print("{d}/{d} {s}...", .{ index + 1, builtin.test_functions.len, test_fn.name });
        if (test_fn.func()) |_| {
            passed += 1;
            std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skipped += 1;
                std.debug.print("SKIP\n", .{});
            },
            else => {
                failed += 1;
                std.debug.print("FAIL ({t})\n", .{err});
                if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            },
        }

        std.testing.io_instance.deinit();
        if (std.testing.allocator_instance.deinit() == .leak) leaked += 1;
    }

    std.debug.print("{d} passed; {d} skipped; {d} failed; {d} leaked\n", .{
        passed, skipped, failed, leaked,
    });
    if (failed != 0 or leaked != 0) std.process.exit(1);
}

fn log(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    std.log.defaultLog(level, scope, format, args);
}
