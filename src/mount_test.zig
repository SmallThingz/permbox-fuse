const std = @import("std");
const permfuse = @import("permfuse");
const terminal = @import("terminal.zig");

pub fn getLogger(comptime module_name: []const u8) type {
    return struct {
        pub fn log(
            comptime src: std.builtin.SourceLocation,
            comptime level: std.log.Level,
            comptime format: []const u8,
            args: anytype,
        ) void {
            terminal.log(module_name, src, level, format, args);
        }
    };
}

pub fn main(init: std.process.Init) !u8 {
    const raw_args = init.minimal.args.vector;
    const parsed_args = try init.gpa.alloc([:0]const u8, raw_args.len);
    defer init.gpa.free(parsed_args);
    for (raw_args, parsed_args) |arg, *parsed| parsed.* = std.mem.span(arg);

    var config = permfuse.options.parse(parsed_args) catch |err| {
        std.debug.print(
            "permfuse-mount-test: {t}\nusage: zig build run-mount-test -- --lower=/absolute/path --policy=/absolute/trie --session=/absolute/session mountpoint [FUSE options]\n",
            .{err},
        );
        return 2;
    };
    defer config.deinit();

    var driver: permfuse.Driver = undefined;
    driver.init(init.io, .{
        .lower_path = config.lower,
        .policy_path = config.policy,
        .session_path = config.session,
        .passthrough = config.passthrough,
    }) catch |err| {
        std.debug.print("permfuse-mount-test: initialization failed: {t}\n", .{err});
        return 1;
    };
    defer driver.deinit();

    var extra = std.ArrayList([:0]const u8).empty;
    defer extra.deinit(init.gpa);
    // Skip parser-generated argv[0], -o and defaults. Driver supplies those
    // defaults and the mountpoint itself.
    for (config.fuse_args[3..]) |arg| {
        if (!std.mem.eql(u8, arg, config.mountpoint))
            try extra.append(init.gpa, arg);
    }

    driver.mount(init.gpa, config.mountpoint, .{
        .io_uring = config.io_uring,
        .arguments = extra.items,
    }) catch |err| {
        std.debug.print("permfuse-mount-test: mount failed: {t}\n", .{err});
        return 1;
    };
    return 0;
}
