//! Embeddable policy FUSE driver backed by a private kernel OverlayFS mount.
const std = @import("std");
const permtrie = @import("permtrie");
const filesystem = @import("fs.zig");
const overlay = @import("overlay.zig");
const policy = @import("policy.zig");
const log = @import("log.zig");

pub const c = filesystem.c;
pub const Access = policy.Access;
pub const Operation = filesystem.Operation;
pub const AskRequest = filesystem.AskRequest;
pub const AskFn = filesystem.AskFn;
pub const OverlaySession = overlay.Session;
pub const OverlayMountOptions = overlay.MountOptions;
pub const ApplyOptions = overlay.ApplyOptions;
pub const ApplyResult = overlay.ApplyResult;
pub const parseAccessText = permtrie.parseAccessText;
pub const options = @import("options.zig");

var driver_active: std.atomic.Value(bool) = .init(false);

pub const Config = struct {
    lower_path: [:0]const u8,
    policy_path: [:0]const u8,
    session_path: [:0]const u8,
    passthrough: bool = true,
    ask_context: ?*anyopaque = null,
    ask_fn: ?AskFn = null,
    overlay: overlay.MountOptions = .{},
};

pub const MountOptions = struct {
    io_uring: bool = true,
    arguments: []const [:0]const u8 = &.{},
};

pub const RuleUpdate = union(enum) {
    set: struct {
        path: []const u8,
        access: Access,
    },
    remove: []const u8,
};

pub const Driver = struct {
    io: std.Io,
    lower_path: [:0]u8,
    passthrough: bool,
    ask_context: ?*anyopaque,
    ask_fn: ?AskFn,
    overlay_options: overlay.MountOptions,
    overlay_session: overlay.Session,
    fs: ?filesystem.Fs = null,
    mount_mutex: std.Io.Mutex = .init,
    mounting: bool = false,
    mounted_session: std.atomic.Value(usize) = .init(0),

    pub fn init(self: *Driver, io: std.Io, config: Config) !void {
        if (driver_active.cmpxchgStrong(false, true, .acq_rel, .acquire) != null)
            return error.DriverAlreadyActive;
        errdefer driver_active.store(false, .release);

        const policy_fd = c.open(
            config.policy_path.ptr,
            c.O_RDWR | c.O_CREAT | c.O_CLOEXEC | c.O_NOFOLLOW,
            @as(c.mode_t, 0o600),
        );
        if (policy_fd < 0) return error.OpenPolicyFailed;
        policy.init(io, policy_fd) catch |err| {
            _ = c.close(policy_fd);
            return err;
        };
        errdefer policy.deinit();

        const lower_path = try std.heap.c_allocator.dupeZ(u8, config.lower_path);
        errdefer std.heap.c_allocator.free(lower_path);
        var session = try overlay.Session.open(io, config.session_path);
        errdefer session.deinit();

        self.* = .{
            .io = io,
            .lower_path = lower_path,
            .passthrough = config.passthrough,
            .ask_context = config.ask_context,
            .ask_fn = config.ask_fn,
            .overlay_options = config.overlay,
            .overlay_session = session,
        };
    }

    pub fn deinit(self: *Driver) void {
        std.debug.assert(self.mounted_session.load(.acquire) == 0);
        std.debug.assert(!self.mounting);
        std.debug.assert(self.fs == null);
        self.overlay_session.deinit();
        std.heap.c_allocator.free(self.lower_path);
        policy.deinit();
        driver_active.store(false, .release);
        self.* = undefined;
    }

    pub fn getRule(self: *Driver, path: []const u8) !?Access {
        _ = self;
        return policy.get(path);
    }

    pub fn evaluate(self: *Driver, path: []const u8) !?Access {
        _ = self;
        return policy.evaluate(path);
    }

    pub fn setRule(self: *Driver, path: []const u8, access: Access) !void {
        _ = self;
        try policy.set(path, access);
    }

    pub fn removeRule(self: *Driver, path: []const u8) !Access {
        _ = self;
        return policy.remove(path);
    }

    pub fn policyToText(self: *Driver, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        return policy.toText(allocator);
    }

    pub fn replacePolicyFromText(
        self: *Driver,
        allocator: std.mem.Allocator,
        text: []const u8,
    ) !void {
        _ = self;
        try policy.replaceFromText(allocator, text);
    }

    pub fn updateRules(self: *Driver, updates: []const RuleUpdate) !void {
        _ = self;
        policy.lockUpdates();
        defer policy.unlockUpdates();
        for (updates) |update| switch (update) {
            .set => |item| try policy.setLocked(item.path, item.access),
            .remove => |path| _ = try policy.removeLocked(path),
        };
    }

    pub fn mount(
        self: *Driver,
        allocator: std.mem.Allocator,
        mountpoint: [:0]const u8,
        mount_options: MountOptions,
    ) !void {
        self.mount_mutex.lockUncancelable(self.io);
        if (self.mounting) {
            self.mount_mutex.unlock(self.io);
            return error.AlreadyMounted;
        }
        self.mounting = true;
        self.mount_mutex.unlock(self.io);
        defer {
            self.mount_mutex.lockUncancelable(self.io);
            self.mounting = false;
            self.mount_mutex.unlock(self.io);
        }

        try self.overlay_session.mount(self.lower_path, self.overlay_options);
        errdefer self.overlay_session.unmount() catch |err|
            log.err(@src(), "failed to roll back private OverlayFS mount: {t}", .{err});
        const root_fd = try self.overlay_session.openMergedRoot();
        self.fs = try filesystem.Fs.init(
            self.io,
            root_fd,
            self.passthrough,
            self.ask_context,
            self.ask_fn,
        );
        defer {
            self.fs.?.deinit();
            self.fs = null;
            self.overlay_session.unmount() catch |err|
                log.err(@src(), "failed to unmount private OverlayFS: {t}", .{err});
        }

        const argv = try allocator.alloc([*c]u8, 4 + mount_options.arguments.len);
        defer allocator.free(argv);
        argv[0] = @constCast("permfuse");
        argv[1] = @constCast("-o");
        argv[2] = @constCast(if (mount_options.io_uring)
            "io_uring,default_permissions"
        else
            "default_permissions");
        argv[3] = @constCast(mountpoint.ptr);
        for (mount_options.arguments, argv[4..]) |argument, *out|
            out.* = @constCast(argument.ptr);

        var args: c.struct_fuse_args = .{
            .argc = @intCast(argv.len),
            .argv = argv.ptr,
            .allocated = 0,
        };
        defer c.fuse_opt_free_args(&args);
        const session = c.fuse_session_new(
            &args,
            &filesystem.ops,
            @sizeOf(c.struct_fuse_lowlevel_ops),
            &self.fs.?,
        ) orelse return error.CreateFuseSessionFailed;
        defer c.fuse_session_destroy(session);

        self.mount_mutex.lockUncancelable(self.io);
        self.mounted_session.store(@intFromPtr(session), .release);
        self.mount_mutex.unlock(self.io);
        defer {
            self.mount_mutex.lockUncancelable(self.io);
            self.mounted_session.store(0, .release);
            self.mount_mutex.unlock(self.io);
        }

        if (c.fuse_set_signal_handlers(session) != 0)
            return error.SignalHandlersFailed;
        defer c.fuse_remove_signal_handlers(session);
        if (c.fuse_session_mount(session, mountpoint.ptr) != 0)
            return error.MountFailed;
        defer c.fuse_session_unmount(session);

        const loop = c.fuse_loop_cfg_create() orelse return error.OutOfMemory;
        defer c.fuse_loop_cfg_destroy(loop);
        c.fuse_loop_cfg_set_clone_fd(loop, 1);
        if (c.fuse_session_loop_mt(session, loop) != 0)
            return error.FuseLoopFailed;
    }

    pub fn requestUnmount(self: *Driver) void {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        const address = self.mounted_session.load(.acquire);
        if (address != 0) c.fuse_session_exit(@ptrFromInt(address));
    }

    pub fn apply(self: *Driver, apply_options: ApplyOptions) !ApplyResult {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        if (self.mounting)
            return error.Mounted;
        return self.overlay_session.apply(self.lower_path, apply_options);
    }

    pub fn discard(self: *Driver, relative_path: []const u8) !void {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        if (self.mounting)
            return error.Mounted;
        try self.overlay_session.discard(relative_path);
    }
};

test "driver owns configuration paths and updates four-state policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.mkdirat(tmp.dir.handle, "lower", @as(c.mode_t, 0o700)),
    );
    var lower_buffer: [128]u8 = undefined;
    var policy_buffer: [128]u8 = undefined;
    var session_buffer: [128]u8 = undefined;
    const lower = try std.fmt.bufPrintZ(&lower_buffer, "/proc/self/fd/{d}/lower", .{tmp.dir.handle});
    const policy_path = try std.fmt.bufPrintZ(&policy_buffer, "/proc/self/fd/{d}/policy", .{tmp.dir.handle});
    const session_path = try std.fmt.bufPrintZ(&session_buffer, "/proc/self/fd/{d}/session", .{tmp.dir.handle});
    var driver: Driver = undefined;
    try driver.init(std.testing.io, .{
        .lower_path = lower,
        .policy_path = policy_path,
        .session_path = session_path,
        .passthrough = false,
    });
    defer driver.deinit();
    try driver.setRule("/", .rw);
    try driver.setRule("/secret", .whiteout);
    try std.testing.expectEqual(Access.rw, (try driver.evaluate("/file")).?);
    try std.testing.expectEqual(Access.whiteout, (try driver.evaluate("/secret/x")).?);
}
