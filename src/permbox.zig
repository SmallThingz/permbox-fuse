//! Public embedding API for the permbox FUSE driver.
const std = @import("std");
const permtrie = @import("permtrie");
const filesystem = @import("fs.zig");
const overlay = @import("overlay.zig");
const policy = @import("policy.zig");

pub const c = filesystem.c;
pub const Mode = policy.Mode;
pub const Operation = filesystem.Operation;
pub const AskRequest = filesystem.AskRequest;
pub const AskDecision = filesystem.AskDecision;
pub const AskFn = filesystem.AskFn;
pub const OverlaySession = overlay.Session;
pub const ApplyOptions = overlay.ApplyOptions;
pub const ApplyResult = overlay.ApplyResult;

var driver_active: std.atomic.Value(bool) = .init(false);

pub const Config = struct {
    /// All path storage must outlive the Driver.
    backing_path: [:0]const u8,
    policy_path: [:0]const u8,
    /// Existing sessions are resumed; missing directories are created.
    state_path: ?[:0]const u8 = null,
    passthrough: bool = true,
    ask_context: ?*anyopaque = null,
    ask_fn: ?AskFn = null,
};

pub const MountOptions = struct {
    io_uring: bool = true,
    /// Additional libfuse arguments. Their storage must remain valid until
    /// `mount` returns.
    arguments: []const [:0]const u8 = &.{},
};

pub const RuleUpdate = union(enum) {
    set: struct {
        path: []const u8,
        mode: Mode,
    },
    remove: []const u8,
};

pub const Driver = struct {
    io: std.Io,
    backing_path: [:0]const u8,
    policy_lock: std.Io.RwLock = .init,
    overlay_session: ?overlay.Session,
    fs: filesystem.Fs,
    mount_mutex: std.Io.Mutex = .init,
    mounted_session: std.atomic.Value(usize) = .init(0),

    /// Initializes `self` in-place because the filesystem retains pointers to
    /// the driver's lock and optional overlay session.
    pub fn init(self: *Driver, io: std.Io, config: Config) !void {
        if (driver_active.cmpxchgStrong(false, true, .acq_rel, .acquire) != null)
            return error.DriverAlreadyActive;
        errdefer driver_active.store(false, .release);

        const policy_fd = c.open(
            config.policy_path.ptr,
            c.O_RDWR | c.O_CREAT | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        if (policy_fd < 0) return error.OpenPolicyFailed;
        permtrie.initIo(io, policy_fd) catch |err| {
            _ = c.close(policy_fd);
            return err;
        };
        errdefer permtrie.deinit();

        self.io = io;
        self.backing_path = config.backing_path;
        self.policy_lock = .init;
        self.mount_mutex = .init;
        self.mounted_session = .init(0);
        self.overlay_session = if (config.state_path) |path|
            try overlay.Session.open(io, path, true)
        else
            null;
        errdefer if (self.overlay_session) |*session| session.deinit();

        const root_fd = c.open(
            config.backing_path.ptr,
            c.O_PATH | c.O_DIRECTORY | c.O_CLOEXEC,
        );
        if (root_fd < 0) return error.OpenBackingFailed;
        self.fs = filesystem.Fs.init(
            io,
            root_fd,
            if (self.overlay_session) |*session| session else null,
            &self.policy_lock,
            config.passthrough,
            config.ask_context,
            config.ask_fn,
        );
    }

    pub fn deinit(self: *Driver) void {
        std.debug.assert(self.mounted_session.load(.acquire) == 0);
        self.fs.deinit();
        if (self.overlay_session) |*session| session.deinit();
        permtrie.deinit();
        driver_active.store(false, .release);
        self.* = undefined;
    }

    pub fn getRule(self: *Driver, path: []const u8) !?Mode {
        self.policy_lock.lockSharedUncancelable(self.io);
        defer self.policy_lock.unlockShared(self.io);
        return policy.get(path);
    }

    pub fn evaluate(self: *Driver, path: []const u8) !?Mode {
        self.policy_lock.lockSharedUncancelable(self.io);
        defer self.policy_lock.unlockShared(self.io);
        return policy.evaluate(path);
    }

    pub fn setRule(self: *Driver, path: []const u8, mode: Mode) !void {
        self.policy_lock.lockUncancelable(self.io);
        defer self.policy_lock.unlock(self.io);
        try policy.set(path, mode);
    }

    pub fn removeRule(self: *Driver, path: []const u8) !Mode {
        self.policy_lock.lockUncancelable(self.io);
        defer self.policy_lock.unlock(self.io);
        return policy.remove(path);
    }

    /// Applies a group under one write-side critical section. If an allocation
    /// or persistence error occurs, preceding updates remain committed.
    pub fn updateRules(self: *Driver, updates: []const RuleUpdate) !void {
        self.policy_lock.lockUncancelable(self.io);
        defer self.policy_lock.unlock(self.io);
        for (updates) |update| switch (update) {
            .set => |item| try policy.set(item.path, item.mode),
            .remove => |path| _ = try policy.remove(path),
        };
    }

    /// Runs the low-level multithreaded FUSE loop until unmounted or
    /// `requestUnmount` is called. Only one mount may be active per driver.
    pub fn mount(
        self: *Driver,
        allocator: std.mem.Allocator,
        mountpoint: [:0]const u8,
        options: MountOptions,
    ) !void {
        if (self.mounted_session.load(.acquire) != 0) return error.AlreadyMounted;

        const base_count: usize = 4;
        const argv = try allocator.alloc([*c]u8, base_count + options.arguments.len);
        defer allocator.free(argv);
        var index: usize = 0;
        argv[index] = @constCast("permbox-fuse");
        index += 1;
        argv[index] = @constCast("-o");
        argv[index + 1] = @constCast(if (options.io_uring)
            "io_uring,default_permissions"
        else
            "default_permissions");
        index += 2;
        argv[index] = @constCast(mountpoint.ptr);
        index += 1;
        for (options.arguments, argv[index..]) |arg, *out| out.* = @constCast(arg.ptr);

        var fuse_args: c.struct_fuse_args = .{
            .argc = @intCast(argv.len),
            .argv = argv.ptr,
            .allocated = 0,
        };
        defer c.fuse_opt_free_args(&fuse_args);

        const session = c.fuse_session_new(
            &fuse_args,
            &filesystem.ops,
            @sizeOf(c.struct_fuse_lowlevel_ops),
            &self.fs,
        ) orelse return error.CreateFuseSessionFailed;
        defer c.fuse_session_destroy(session);
        self.mount_mutex.lockUncancelable(self.io);
        const previous = self.mounted_session.cmpxchgStrong(
            0,
            @intFromPtr(session),
            .acq_rel,
            .acquire,
        );
        self.mount_mutex.unlock(self.io);
        if (previous != null) return error.AlreadyMounted;
        defer self.clearMountedSession();

        if (c.fuse_set_signal_handlers(session) != 0) return error.SignalHandlersFailed;
        defer c.fuse_remove_signal_handlers(session);
        if (c.fuse_session_mount(session, mountpoint.ptr) != 0) return error.MountFailed;
        defer c.fuse_session_unmount(session);

        const loop_config = c.fuse_loop_cfg_create() orelse return error.OutOfMemory;
        defer c.fuse_loop_cfg_destroy(loop_config);
        c.fuse_loop_cfg_set_clone_fd(loop_config, 1);
        if (c.fuse_session_loop_mt(session, loop_config) != 0)
            return error.FuseLoopFailed;
    }

    /// Thread-safe. Causes a running `mount` call to leave its loop and unmount.
    pub fn requestUnmount(self: *Driver) void {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        const address = self.mounted_session.load(.acquire);
        if (address != 0) c.fuse_session_exit(@ptrFromInt(address));
    }

    fn clearMountedSession(self: *Driver) void {
        self.mount_mutex.lockUncancelable(self.io);
        self.mounted_session.store(0, .release);
        self.mount_mutex.unlock(self.io);
    }

    /// Applies a resumable overlay session back to the configured backing
    /// directory. A live mount is rejected because sparse files may be active.
    pub fn applyOverlay(
        self: *Driver,
        allocator: std.mem.Allocator,
        options: ApplyOptions,
    ) !ApplyResult {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        if (self.mounted_session.load(.acquire) != 0) return error.Mounted;
        const session = if (self.overlay_session) |*value| value else return error.NoOverlaySession;
        return session.apply(allocator, self.backing_path, options);
    }
};

test "public mode export matches trie mode" {
    try std.testing.expectEqual(@sizeOf(permtrie.Mode), @sizeOf(Mode));
}

test "driver creates and updates policy through caller Io" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.mkdirat(tmp.dir.handle, "backing", @as(c.mode_t, 0o700)),
    );
    var backing_buf: [128]u8 = undefined;
    const backing = try std.fmt.bufPrintZ(
        &backing_buf,
        "/proc/self/fd/{d}/backing",
        .{tmp.dir.handle},
    );
    var policy_buf: [128]u8 = undefined;
    const policy_path = try std.fmt.bufPrintZ(
        &policy_buf,
        "/proc/self/fd/{d}/policy",
        .{tmp.dir.handle},
    );

    var driver: Driver = undefined;
    try driver.init(std.testing.io, .{
        .backing_path = backing,
        .policy_path = policy_path,
        .passthrough = false,
    });
    defer driver.deinit();
    try driver.setRule("/", Mode.dir);
    const inherited = (try driver.evaluate("/child")).?;
    try std.testing.expectEqual(@as(u8, @bitCast(Mode.dir)), @as(u8, @bitCast(inherited)));
}
