const std = @import("std");
const permtrie = @import("permtrie");
const filesystem = @import("fs.zig");
const options = @import("options.zig");

const c = filesystem.c;

pub fn getLogger(comptime module_name: []const u8) type {
    return struct {
        pub fn log(
            comptime level: std.log.Level,
            comptime format: []const u8,
            args: anytype,
        ) void {
            std.log.defaultLog(level, .default, "(" ++ module_name ++ ") " ++ format, args);
        }
    };
}

pub fn main(minimal_init: std.process.Init.Minimal) !u8 {
    const page = std.heap.page_allocator;
    const raw_args = minimal_init.args.vector;
    const parsed_args = try page.alloc([:0]const u8, raw_args.len);
    defer page.free(parsed_args);
    for (raw_args, parsed_args) |arg, *parsed| parsed.* = std.mem.span(arg);

    var config = options.parse(parsed_args) catch |err| {
        std.debug.print(
            "permbox-fuse: {t}\nusage: permbox-fuse --backing=/absolute/path --policy=/absolute/trie [--state=/absolute/path] mountpoint [FUSE options]\n",
            .{err},
        );
        return 2;
    };
    defer config.deinit();

    const policy_fd = c.open(config.policy.ptr, c.O_RDWR | c.O_CREAT | c.O_CLOEXEC, @as(c.mode_t, 0o600));
    if (policy_fd < 0) {
        std.debug.print("permbox-fuse: cannot open policy trie {s}: errno {d}\n", .{ config.policy, c.__errno_location().* });
        return 1;
    }
    try permtrie.init(policy_fd);
    defer permtrie.deinit();

    const root_fd = c.open(config.backing.ptr, c.O_PATH | c.O_DIRECTORY | c.O_CLOEXEC);
    if (root_fd < 0) {
        std.debug.print("permbox-fuse: cannot open backing directory {s}: errno {d}\n", .{ config.backing, c.__errno_location().* });
        return 1;
    }
    const state_fd = if (config.state) |state_path| blk: {
        const fd = c.open(state_path.ptr, c.O_PATH | c.O_DIRECTORY | c.O_CLOEXEC);
        if (fd < 0) {
            std.debug.print("permbox-fuse: cannot open state directory {s}: errno {d}\n", .{ state_path, c.__errno_location().* });
            return 1;
        }
        break :blk fd;
    } else -1;
    var fs = filesystem.Fs.init(root_fd, state_fd, config.passthrough);
    defer fs.deinit();

    const c_argv = try page.alloc([*c]u8, config.fuse_args.len);
    defer page.free(c_argv);
    for (config.fuse_args, c_argv) |arg, *out| out.* = @constCast(arg.ptr);
    var fuse_args: c.struct_fuse_args = .{
        .argc = @intCast(c_argv.len),
        .argv = c_argv.ptr,
        .allocated = 0,
    };
    defer c.fuse_opt_free_args(&fuse_args);

    const session = c.fuse_session_new(&fuse_args, &filesystem.ops, @sizeOf(c.struct_fuse_lowlevel_ops), &fs) orelse {
        std.debug.print("permbox-fuse: fuse_session_new failed\n", .{});
        return 1;
    };
    defer c.fuse_session_destroy(session);

    if (c.fuse_set_signal_handlers(session) != 0) return 1;
    defer c.fuse_remove_signal_handlers(session);

    if (c.fuse_session_mount(session, config.mountpoint.ptr) != 0) return 1;
    defer c.fuse_session_unmount(session);

    const loop_config = c.fuse_loop_cfg_create() orelse return error.OutOfMemory;
    defer c.fuse_loop_cfg_destroy(loop_config);
    c.fuse_loop_cfg_set_clone_fd(loop_config, 1);

    return if (c.fuse_session_loop_mt(session, loop_config) == 0) 0 else 1;
}
