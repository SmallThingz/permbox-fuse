//! Reusable policy-aware FUSE driver for embedding in permbox.
const std = @import("std");
const permtrie = @import("permtrie");
const filesystem = @import("fs.zig");
const overlay = @import("overlay.zig");
const policy = @import("policy.zig");
const log = @import("log.zig");

pub const c = filesystem.c;
pub const Mode = policy.Mode;
pub const Operation = filesystem.Operation;
pub const AskRequest = filesystem.AskRequest;
pub const AskDecision = filesystem.AskDecision;
pub const AskFn = filesystem.AskFn;
pub const OverlaySession = overlay.Session;
pub const ApplyOptions = overlay.ApplyOptions;
pub const ApplyResult = overlay.ApplyResult;
pub const parseModeText = permtrie.parseModeText;

pub const options = @import("options.zig");

var driver_active: std.atomic.Value(bool) = .init(false);

pub const Config = struct {
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
    backing_path: [:0]u8,
    overlay_session: ?*overlay.Session,
    fs: filesystem.Fs,
    mount_mutex: std.Io.Mutex = .init,
    mounted_session: std.atomic.Value(usize) = .init(0),

    /// Initializes `self` in-place. The value must not be moved while mounted,
    /// because libfuse retains `&self.fs` as callback userdata.
    pub fn init(self: *Driver, io: std.Io, config: Config) !void {
        if (driver_active.cmpxchgStrong(false, true, .acq_rel, .acquire) != null)
            return error.DriverAlreadyActive;
        errdefer driver_active.store(false, .release);

        const policy_fd = c.open(
            config.policy_path.ptr,
            c.O_RDWR | c.O_CREAT | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        if (policy_fd < 0) {
            log.err(@src(), "open policy path failed; path={s}, errno={}", .{
                config.policy_path,
                @intFromEnum(std.posix.errno(policy_fd)),
            });
            return error.OpenPolicyFailed;
        }
        policy.init(io, policy_fd) catch |err| {
            log.err(@src(), "policy trie init failed; fd={}, err={t}", .{ policy_fd, err });
            _ = c.close(policy_fd);
            return err;
        };
        errdefer policy.deinit();

        self.io = io;
        self.backing_path = std.heap.c_allocator.dupeZ(u8, config.backing_path) catch
            return error.OutOfMemory;
        errdefer std.heap.c_allocator.free(self.backing_path);
        self.mount_mutex = .init;
        self.mounted_session = .init(0);
        self.overlay_session = if (config.state_path) |path| blk: {
            const session = std.heap.c_allocator.create(overlay.Session) catch
                return error.OutOfMemory;
            errdefer std.heap.c_allocator.destroy(session);
            session.* = overlay.Session.open(io, path, true) catch |err| {
                log.err(@src(), "open overlay session failed; path={s}, err={t}", .{ path, err });
                return err;
            };
            break :blk session;
        } else null;
        errdefer if (self.overlay_session) |session| {
            session.deinit();
            std.heap.c_allocator.destroy(session);
        };

        const root_fd = c.open(
            config.backing_path.ptr,
            c.O_PATH | c.O_DIRECTORY | c.O_CLOEXEC,
        );
        if (root_fd < 0) {
            log.err(@src(), "open backing path failed; path={s}, errno={}", .{
                config.backing_path,
                @intFromEnum(std.posix.errno(root_fd)),
            });
            return error.OpenBackingFailed;
        }
        self.fs = filesystem.Fs.init(
            io,
            root_fd,
            self.overlay_session,
            config.passthrough,
            config.ask_context,
            config.ask_fn,
        );
    }

    pub fn deinit(self: *Driver) void {
        std.debug.assert(self.mounted_session.load(.acquire) == 0);
        self.fs.deinit();
        if (self.overlay_session) |session| {
            session.deinit();
            std.heap.c_allocator.destroy(session);
        }
        std.heap.c_allocator.free(self.backing_path);
        policy.deinit();
        driver_active.store(false, .release);
        self.* = undefined;
    }

    pub fn getRule(self: *Driver, path: []const u8) !?Mode {
        _ = self;
        return policy.get(path);
    }

    pub fn evaluate(self: *Driver, path: []const u8) !?Mode {
        _ = self;
        return policy.evaluate(path);
    }

    pub fn setRule(self: *Driver, path: []const u8, mode: Mode) !void {
        _ = self;
        try policy.set(path, mode);
    }

    pub fn removeRule(self: *Driver, path: []const u8) !Mode {
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

    /// Applies a group under one write-side critical section. If an allocation
    /// or persistence error occurs, preceding updates remain committed.
    pub fn updateRules(self: *Driver, updates: []const RuleUpdate) !void {
        _ = self;
        policy.lockUpdates();
        defer policy.unlockUpdates();
        for (updates) |update| switch (update) {
            .set => |item| try policy.setLocked(item.path, item.mode),
            .remove => |path| _ = try policy.removeLocked(path),
        };
    }

    /// Runs the low-level multithreaded FUSE loop until unmounted or
    /// `requestUnmount` is called. Only one mount may be active per driver.
    pub fn mount(
        self: *Driver,
        allocator: std.mem.Allocator,
        mountpoint: [:0]const u8,
        mount_options: MountOptions,
    ) !void {
        if (self.mounted_session.load(.acquire) != 0) {
            log.warn(@src(), "mount called but session already active; mountpoint={s}", .{mountpoint});
            return error.AlreadyMounted;
        }

        const base_count: usize = 4;
        const argv = try allocator.alloc([*c]u8, base_count + mount_options.arguments.len);
        defer allocator.free(argv);
        var index: usize = 0;
        argv[index] = @constCast("permfuse");
        index += 1;
        argv[index] = @constCast("-o");
        argv[index + 1] = @constCast(if (mount_options.io_uring)
            "io_uring,default_permissions"
        else
            "default_permissions");
        index += 2;
        argv[index] = @constCast(mountpoint.ptr);
        index += 1;
        for (mount_options.arguments, argv[index..]) |arg, *out| out.* = @constCast(arg.ptr);

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
        ) orelse {
            log.err(@src(), "fuse_session_new failed; mountpoint={s}", .{mountpoint});
            return error.CreateFuseSessionFailed;
        };
        defer c.fuse_session_destroy(session);
        self.mount_mutex.lockUncancelable(self.io);
        const previous = self.mounted_session.cmpxchgStrong(
            0,
            @intFromPtr(session),
            .acq_rel,
            .acquire,
        );
        self.mount_mutex.unlock(self.io);
        if (previous != null) {
            log.warn(@src(), "mount raced with another session; mountpoint={s}", .{mountpoint});
            return error.AlreadyMounted;
        }
        defer self.clearMountedSession();

        if (c.fuse_set_signal_handlers(session) != 0) {
            log.err(@src(), "fuse_set_signal_handlers failed; mountpoint={s}", .{mountpoint});
            return error.SignalHandlersFailed;
        }
        defer c.fuse_remove_signal_handlers(session);
        if (c.fuse_session_mount(session, mountpoint.ptr) != 0) {
            log.err(@src(), "fuse_session_mount failed; mountpoint={s}", .{mountpoint});
            return error.MountFailed;
        }
        defer c.fuse_session_unmount(session);

        const loop_config = c.fuse_loop_cfg_create() orelse {
            log.err(@src(), "fuse_loop_cfg_create OOM; mountpoint={s}", .{mountpoint});
            return error.OutOfMemory;
        };
        defer c.fuse_loop_cfg_destroy(loop_config);
        c.fuse_loop_cfg_set_clone_fd(loop_config, 1);
        if (c.fuse_session_loop_mt(session, loop_config) != 0) {
            log.err(@src(), "FUSE session loop failed; mountpoint={s}", .{mountpoint});
            return error.FuseLoopFailed;
        }
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
        apply_options: ApplyOptions,
    ) !ApplyResult {
        self.mount_mutex.lockUncancelable(self.io);
        defer self.mount_mutex.unlock(self.io);
        if (self.mounted_session.load(.acquire) != 0) {
            log.warn(@src(), "applyOverlay rejected; mount is active", .{});
            return error.Mounted;
        }
        const session = self.overlay_session orelse {
            log.warn(@src(), "applyOverlay rejected; no overlay session configured", .{});
            return error.NoOverlaySession;
        };
        return session.apply(allocator, self.backing_path, apply_options);
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
    try std.testing.expect(driver.backing_path.ptr != backing.ptr);
    backing_buf[0] = '!';
    try std.testing.expectEqual(@as(u8, '/'), driver.backing_path[0]);
    try driver.setRule("/", Mode.dir);
    const inherited = (try driver.evaluate("/child")).?;
    try std.testing.expectEqual(@as(u8, @bitCast(Mode.dir)), @as(u8, @bitCast(inherited)));
}
