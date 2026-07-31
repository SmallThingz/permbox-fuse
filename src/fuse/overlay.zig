//! Private kernel OverlayFS session lifecycle.
const std = @import("std");
const log = @import("log.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("errno.h");
    @cInclude("dirent.h");
    @cInclude("fcntl.h");
    @cInclude("stdio.h");
    @cInclude("sys/file.h");
    @cInclude("sys/mount.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/xattr.h");
    @cInclude("unistd.h");
});

var temporary_counter: std.atomic.Value(u64) = .init(0);
const internal_trash = ".permfs-internal-trash";

pub const MountOptions = struct {
    redirect_dir: bool = true,
    index: bool = true,
    xino_auto: bool = true,
};

pub const ApplyOptions = struct {
    max_entries: ?usize = null,
};

pub const ApplyResult = struct {
    applied: usize = 0,
    remaining: usize = 0,

    pub fn complete(self: ApplyResult) bool {
        return self.remaining == 0;
    }
};

pub const Session = struct {
    io: std.Io,
    root: [:0]u8,
    upper: [:0]u8,
    work: [:0]u8,
    merged: [:0]u8,
    lock_fd: c_int,
    mounted: bool = false,
    index_enabled: bool = false,

    pub fn open(io: std.Io, path: [:0]const u8) !Session {
        try std.Io.Dir.cwd().createDirPath(io, path);
        const allocator = std.heap.c_allocator;
        const root = try allocator.dupeZ(u8, path);
        errdefer allocator.free(root);
        try ensureDirectory(root);
        const upper = try childPath(allocator, path, "upper");
        errdefer allocator.free(upper);
        const work = try childPath(allocator, path, "work");
        errdefer allocator.free(work);
        const merged = try childPath(allocator, path, "merged");
        errdefer allocator.free(merged);
        const lock_path = try childPath(allocator, path, "lock");
        defer allocator.free(lock_path);

        try ensureDirectory(upper);
        try ensureDirectory(work);
        try ensureDirectory(merged);

        const lock_fd = c.open(
            lock_path.ptr,
            c.O_RDWR | c.O_CREAT | c.O_CLOEXEC | c.O_NOFOLLOW,
            @as(c.mode_t, 0o600),
        );
        if (lock_fd < 0) return error.OpenSessionLockFailed;
        errdefer _ = c.close(lock_fd);
        if (c.flock(lock_fd, c.LOCK_EX | c.LOCK_NB) != 0)
            return error.SessionBusy;

        return .{
            .io = io,
            .root = root,
            .upper = upper,
            .work = work,
            .merged = merged,
            .lock_fd = lock_fd,
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.mounted) self.unmount() catch |err|
            log.err(@src(), "failed to unmount OverlayFS during deinit: {t}", .{err});
        _ = c.flock(self.lock_fd, c.LOCK_UN);
        _ = c.close(self.lock_fd);
        const allocator = std.heap.c_allocator;
        allocator.free(self.merged);
        allocator.free(self.work);
        allocator.free(self.upper);
        allocator.free(self.root);
        self.* = undefined;
    }

    pub fn mount(self: *Session, lower: [:0]const u8, options: MountOptions) !void {
        if (self.mounted) return error.AlreadyMounted;

        if (options.index) {
            self.mountWith(lower, options, true) catch |err| {
                log.warn(@src(), "OverlayFS index unavailable, retrying without it: {t}", .{err});
                try self.mountWith(lower, options, false);
                self.index_enabled = false;
                self.mounted = true;
                return;
            };
            self.index_enabled = true;
        } else {
            try self.mountWith(lower, options, false);
            self.index_enabled = false;
        }
        self.mounted = true;
    }

    fn mountWith(
        self: *Session,
        lower: [:0]const u8,
        options: MountOptions,
        index: bool,
    ) !void {
        const mount_data = try std.fmt.allocPrintSentinel(
            std.heap.c_allocator,
            "lowerdir={s},upperdir={s},workdir={s},redirect_dir={s},index={s},xino={s},metacopy=off",
            .{
                lower,
                self.upper,
                self.work,
                if (options.redirect_dir) "on" else "off",
                if (index) "on" else "off",
                if (options.xino_auto) "auto" else "off",
            },
            0,
        );
        defer std.heap.c_allocator.free(mount_data);
        const rc = c.mount("overlay", self.merged.ptr, "overlay", 0, mount_data.ptr);
        if (rc != 0) {
            log.err(@src(), "OverlayFS mount failed; merged={s}, errno={}", .{
                self.merged,
                @intFromEnum(std.c.errno(rc)),
            });
            return error.OverlayMountFailed;
        }
    }

    pub fn unmount(self: *Session) !void {
        if (!self.mounted) return;
        const rc = c.umount2(self.merged.ptr, 0);
        if (rc != 0) return error.OverlayUnmountFailed;
        self.mounted = false;
    }

    pub fn openMergedRoot(self: *Session) !c_int {
        if (!self.mounted) return error.NotMounted;
        const fd = c.open(
            self.merged.ptr,
            c.O_PATH | c.O_DIRECTORY | c.O_CLOEXEC | c.O_NOFOLLOW,
        );
        if (fd < 0) return error.OpenMergedRootFailed;
        return fd;
    }

    /// Apply a bounded number of upper entries. The upper tree is the durable
    /// checkpoint: an entry is removed only after its lower operation and
    /// destination directory have been synced.
    pub fn apply(
        self: *Session,
        lower: [:0]const u8,
        options: ApplyOptions,
    ) !ApplyResult {
        if (self.mounted) return error.SessionMounted;
        var result: ApplyResult = .{};
        var budget = options.max_entries orelse std.math.maxInt(usize);
        const trash = try childPath(std.heap.c_allocator, self.upper, internal_trash);
        defer std.heap.c_allocator.free(trash);
        removeTree(trash) catch |err| if (err != error.NotFound) return err;
        var links: std.AutoHashMapUnmanaged(u128, [:0]u8) = .empty;
        defer {
            var iterator = links.valueIterator();
            while (iterator.next()) |path| std.heap.c_allocator.free(path.*);
            links.deinit(std.heap.c_allocator);
        }
        try applyDirectory(self.upper, lower, lower, &budget, &result, &links, true);
        result.remaining = try countEntries(self.upper);
        return result;
    }

    pub fn discard(self: *Session, relative_path: []const u8) !void {
        if (self.mounted) return error.SessionMounted;
        if (!validRelative(relative_path)) return error.InvalidPath;
        const target = try childPath(std.heap.c_allocator, self.upper, relative_path);
        defer std.heap.c_allocator.free(target);
        try removeTree(target);
        try syncParent(target);
    }
};

fn childPath(allocator: std.mem.Allocator, parent: []const u8, child: []const u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(
        allocator,
        "{s}{s}{s}",
        .{ parent, if (parent.len == 1) "" else "/", child },
        0,
    );
}

fn ensureDirectory(path: [:0]const u8) !void {
    const rc = c.mkdir(path.ptr, @as(c.mode_t, 0o700));
    if (rc != 0 and std.c.errno(rc) != .EXIST)
        return error.CreateSessionDirectoryFailed;
    var st: c.struct_stat = undefined;
    if (c.lstat(path.ptr, &st) != 0 or st.st_mode & c.S_IFMT != c.S_IFDIR)
        return error.InvalidSessionDirectory;
}

fn applyDirectory(
    upper: [:0]const u8,
    lower: [:0]const u8,
    lower_root: [:0]const u8,
    budget: *usize,
    result: *ApplyResult,
    links: *std.AutoHashMapUnmanaged(u128, [:0]u8),
    root: bool,
) !void {
    if (!root) try applyRedirect(upper, lower, lower_root);
    if (!root and opaqueDirectory(upper)) {
        removeTree(lower) catch |err| if (err != error.NotFound) return err;
    }
    try ensureDirectory(lower);
    const names = try directoryNames(upper);
    defer freeNames(names);
    for (names) |name| {
        const upper_child = try childPath(std.heap.c_allocator, upper, name);
        defer std.heap.c_allocator.free(upper_child);
        const lower_child = try childPath(std.heap.c_allocator, lower, name);
        defer std.heap.c_allocator.free(lower_child);
        var st: c.struct_stat = undefined;
        if (c.lstat(upper_child.ptr, &st) != 0)
            return error.StatUpperEntryFailed;

        if (st.st_mode & c.S_IFMT == c.S_IFDIR) {
            try applyDirectory(upper_child, lower_child, lower_root, budget, result, links, false);
            if (try countEntries(upper_child) == 0) {
                clearOverlayXattrs(upper_child);
                _ = c.rmdir(upper_child.ptr);
            }
            continue;
        }
        const hardlink_key: ?u128 = if (st.st_mode & c.S_IFMT == c.S_IFREG)
            (@as(u128, @intCast(st.st_dev)) << 64) | @as(u128, @intCast(st.st_ino))
        else
            null;
        const completes_hardlink_group = if (hardlink_key) |key| links.contains(key) else false;
        if (budget.* == 0 and !completes_hardlink_group) continue;
        if (whiteout(st, upper_child)) {
            removeTree(lower_child) catch |err| if (err != error.NotFound) return err;
        } else {
            try publishEntry(upper_child, lower_child, st, links);
        }
        try syncParent(lower_child);
        if (c.unlink(upper_child.ptr) != 0)
            return error.RemoveAppliedUpperFailed;
        try syncParent(upper_child);
        if (budget.* != 0) budget.* -= 1;
        result.applied += 1;
    }
    if (!root) try copyDirectoryMetadata(upper, lower);
}

fn applyRedirect(upper: [:0]const u8, destination: [:0]const u8, lower_root: [:0]const u8) !void {
    var redirect_buffer: [max_path]u8 = undefined;
    var length: isize = -1;
    inline for (.{ "trusted.overlay.redirect", "user.overlay.redirect" }) |name| {
        length = c.lgetxattr(upper.ptr, name, &redirect_buffer, redirect_buffer.len - 1);
        if (length >= 0) break;
    }
    if (length < 0) return;
    const raw = redirect_buffer[0..@intCast(length)];
    const relative = std.mem.trimStart(u8, raw, "/");
    if (!validRelative(relative)) return error.InvalidRedirect;
    const source = try childPath(std.heap.c_allocator, lower_root, relative);
    defer std.heap.c_allocator.free(source);
    var source_stat: c.struct_stat = undefined;
    if (c.lstat(source.ptr, &source_stat) != 0) {
        if (std.c.errno(-1) == .NOENT) return;
        return error.StatRedirectSourceFailed;
    }
    removeTree(destination) catch |err| if (err != error.NotFound) return err;
    if (c.rename(source.ptr, destination.ptr) != 0)
        return error.ApplyRedirectFailed;
    try syncParent(source);
    try syncParent(destination);
}

fn publishEntry(
    source: [:0]const u8,
    destination: [:0]const u8,
    st: c.struct_stat,
    links: *std.AutoHashMapUnmanaged(u128, [:0]u8),
) !void {
    const temporary = try temporaryPath(destination);
    defer std.heap.c_allocator.free(temporary);
    _ = c.unlink(temporary.ptr);
    const kind = st.st_mode & c.S_IFMT;
    const link_key: ?u128 = if (kind == c.S_IFREG)
        (@as(u128, @intCast(st.st_dev)) << 64) | @as(u128, @intCast(st.st_ino))
    else
        null;
    if (kind == c.S_IFREG) {
        var linked = false;
        if (link_key) |key| {
            if (links.get(key)) |first| {
                if (c.link(first.ptr, temporary.ptr) != 0)
                    return error.CreateApplyHardLinkFailed;
                linked = true;
            }
        }
        if (!linked) {
            try copyRegular(source, temporary, st);
        }
    } else if (kind == c.S_IFLNK) {
        var target: [max_path]u8 = undefined;
        const length = c.readlink(source.ptr, &target, target.len - 1);
        if (length < 0) return error.ReadSymlinkFailed;
        target[@intCast(length)] = 0;
        if (c.symlink(@ptrCast(&target), temporary.ptr) != 0)
            return error.CreateSymlinkFailed;
    } else {
        if (c.mknod(temporary.ptr, st.st_mode, st.st_rdev) != 0)
            return error.CreateSpecialFileFailed;
    }
    if (kind != c.S_IFLNK) {
        _ = c.chown(temporary.ptr, st.st_uid, st.st_gid);
        _ = c.chmod(temporary.ptr, st.st_mode & 0o7777);
        try copyXattrs(source, temporary);
        const times = [_]c.struct_timespec{ st.st_atim, st.st_mtim };
        _ = c.utimensat(c.AT_FDCWD, temporary.ptr, &times, 0);
    }
    if (c.rename(temporary.ptr, destination.ptr) != 0)
        return error.PublishEntryFailed;
    if (link_key) |key| {
        if (!links.contains(key)) {
            const owned = try std.heap.c_allocator.dupeZ(u8, destination);
            errdefer std.heap.c_allocator.free(owned);
            try links.put(std.heap.c_allocator, key, owned);
        }
    }
}

const max_path = 4096;

fn copyRegular(source: [:0]const u8, temporary: [:0]const u8, st: c.struct_stat) !void {
    const source_fd = c.open(source.ptr, c.O_RDONLY | c.O_CLOEXEC | c.O_NOFOLLOW);
    if (source_fd < 0) return error.OpenUpperFileFailed;
    defer _ = c.close(source_fd);
    const destination_fd = c.open(
        temporary.ptr,
        c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC | c.O_NOFOLLOW,
        st.st_mode & 0o7777,
    );
    if (destination_fd < 0) return error.CreateApplyTemporaryFailed;
    errdefer _ = c.unlink(temporary.ptr);
    defer _ = c.close(destination_fd);

    var buffer: [128 * 1024]u8 = undefined;
    while (true) {
        const got = c.read(source_fd, &buffer, buffer.len);
        if (got < 0) return error.ReadUpperFileFailed;
        if (got == 0) break;
        var written: usize = 0;
        while (written < @as(usize, @intCast(got))) {
            const amount = c.write(
                destination_fd,
                buffer[written..].ptr,
                @as(usize, @intCast(got)) - written,
            );
            if (amount <= 0) return error.WriteApplyTemporaryFailed;
            written += @intCast(amount);
        }
    }
    if (c.fsync(destination_fd) != 0) return error.SyncApplyTemporaryFailed;
}

fn copyDirectoryMetadata(source: [:0]const u8, destination: [:0]const u8) !void {
    var st: c.struct_stat = undefined;
    if (c.lstat(source.ptr, &st) != 0) return error.StatUpperEntryFailed;
    _ = c.chown(destination.ptr, st.st_uid, st.st_gid);
    _ = c.chmod(destination.ptr, st.st_mode & 0o7777);
    try copyXattrs(source, destination);
    const times = [_]c.struct_timespec{ st.st_atim, st.st_mtim };
    _ = c.utimensat(c.AT_FDCWD, destination.ptr, &times, 0);
    try syncPath(destination);
}

fn copyXattrs(source: [:0]const u8, destination: [:0]const u8) !void {
    const needed = c.llistxattr(source.ptr, null, 0);
    if (needed <= 0) return;
    const names = try std.heap.c_allocator.alloc(u8, @intCast(needed));
    defer std.heap.c_allocator.free(names);
    const got = c.llistxattr(source.ptr, names.ptr, names.len);
    if (got < 0) return error.ListUpperXattrsFailed;
    var start: usize = 0;
    while (start < @as(usize, @intCast(got))) {
        const end = std.mem.indexOfScalarPos(u8, names, start, 0) orelse break;
        const name = names[start..end :0];
        start = end + 1;
        if (overlayXattr(name)) continue;
        const value_size = c.lgetxattr(source.ptr, name.ptr, null, 0);
        if (value_size < 0) continue;
        const value = try std.heap.c_allocator.alloc(u8, @intCast(value_size));
        defer std.heap.c_allocator.free(value);
        if (c.lgetxattr(source.ptr, name.ptr, value.ptr, value.len) != value_size)
            continue;
        if (c.lsetxattr(destination.ptr, name.ptr, value.ptr, value.len, 0) != 0)
            return error.SetDestinationXattrFailed;
    }
}

fn overlayXattr(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "trusted.overlay.") or
        std.mem.startsWith(u8, name, "user.overlay.");
}

fn clearOverlayXattrs(path: [:0]const u8) void {
    inline for (.{
        "trusted.overlay.opaque",
        "user.overlay.opaque",
        "trusted.overlay.redirect",
        "user.overlay.redirect",
        "trusted.overlay.metacopy",
        "user.overlay.metacopy",
        "trusted.overlay.origin",
        "user.overlay.origin",
    }) |name| _ = c.lremovexattr(path.ptr, name);
}

fn opaqueDirectory(path: [:0]const u8) bool {
    var value: [1]u8 = undefined;
    inline for (.{ "trusted.overlay.opaque", "user.overlay.opaque" }) |name| {
        if (c.lgetxattr(path.ptr, name, &value, 1) == 1 and
            (value[0] == 'y' or value[0] == 'x'))
            return true;
    }
    return false;
}

fn whiteout(st: c.struct_stat, path: [:0]const u8) bool {
    if (st.st_mode & c.S_IFMT == c.S_IFCHR and st.st_rdev == 0) return true;
    var value: [1]u8 = undefined;
    inline for (.{ "trusted.overlay.whiteout", "user.overlay.whiteout" }) |name|
        if (c.lgetxattr(path.ptr, name, &value, 1) >= 0) return true;
    return false;
}

fn removeTree(path: [:0]const u8) !void {
    var st: c.struct_stat = undefined;
    if (c.lstat(path.ptr, &st) != 0) {
        if (std.c.errno(-1) == .NOENT) return error.NotFound;
        return error.StatRemoveTargetFailed;
    }
    if (st.st_mode & c.S_IFMT != c.S_IFDIR)
        return if (c.unlink(path.ptr) == 0) {} else error.RemoveTargetFailed;
    const names = try directoryNames(path);
    defer freeNames(names);
    for (names) |name| {
        const child = try childPath(std.heap.c_allocator, path, name);
        defer std.heap.c_allocator.free(child);
        try removeTree(child);
    }
    if (c.rmdir(path.ptr) != 0) return error.RemoveDirectoryFailed;
}

fn directoryNames(path: [:0]const u8) ![][:0]u8 {
    const directory = c.opendir(path.ptr) orelse return error.OpenUpperDirectoryFailed;
    defer _ = c.closedir(directory);
    var names: std.ArrayList([:0]u8) = .empty;
    errdefer {
        for (names.items) |name| std.heap.c_allocator.free(name);
        names.deinit(std.heap.c_allocator);
    }
    while (c.readdir(directory)) |entry| {
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        try names.append(std.heap.c_allocator, try std.heap.c_allocator.dupeZ(u8, name));
    }
    return names.toOwnedSlice(std.heap.c_allocator);
}

fn freeNames(names: [][:0]u8) void {
    for (names) |name| std.heap.c_allocator.free(name);
    std.heap.c_allocator.free(names);
}

fn countEntries(path: [:0]const u8) !usize {
    const directory = c.opendir(path.ptr) orelse return error.OpenUpperDirectoryFailed;
    defer _ = c.closedir(directory);
    var count: usize = 0;
    while (c.readdir(directory)) |entry| {
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        const child = try childPath(std.heap.c_allocator, path, name);
        defer std.heap.c_allocator.free(child);
        var st: c.struct_stat = undefined;
        if (c.lstat(child.ptr, &st) != 0) continue;
        count += if (st.st_mode & c.S_IFMT == c.S_IFDIR)
            try countEntries(child)
        else
            1;
    }
    return count;
}

fn temporaryPath(destination: [:0]const u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(
        std.heap.c_allocator,
        "{s}.permfs-{d}-{d}",
        .{ destination, c.getpid(), temporary_counter.fetchAdd(1, .monotonic) },
        0,
    );
}

fn syncPath(path: [:0]const u8) !void {
    const fd = c.open(path.ptr, c.O_RDONLY | c.O_CLOEXEC | c.O_NOFOLLOW);
    if (fd < 0) return error.OpenSyncTargetFailed;
    defer _ = c.close(fd);
    if (c.fsync(fd) != 0) return error.SyncTargetFailed;
}

fn syncParent(path: [:0]const u8) !void {
    const parent = std.fs.path.dirname(path) orelse "/";
    const parent_z = try std.heap.c_allocator.dupeZ(u8, parent);
    defer std.heap.c_allocator.free(parent_z);
    try syncPath(parent_z);
}

fn validRelative(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return false;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component|
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    return true;
}

test "session paths are deterministic and exclusively locked" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "/proc/self/fd/{d}/session", .{tmp.dir.handle});
    var session = try Session.open(std.testing.io, path);
    defer session.deinit();
    try std.testing.expect(std.mem.endsWith(u8, session.upper, "/upper"));
    try std.testing.expectError(error.SessionBusy, Session.open(std.testing.io, path));
}

test "bounded apply drains ordinary upper files and resumes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.mkdirat(tmp.dir.handle, "lower", @as(c.mode_t, 0o700)),
    );
    var session_buffer: [128]u8 = undefined;
    var lower_buffer: [128]u8 = undefined;
    const session_path = try std.fmt.bufPrintZ(
        &session_buffer,
        "/proc/self/fd/{d}/session",
        .{tmp.dir.handle},
    );
    const lower_path = try std.fmt.bufPrintZ(
        &lower_buffer,
        "/proc/self/fd/{d}/lower",
        .{tmp.dir.handle},
    );
    var session = try Session.open(std.testing.io, session_path);
    defer session.deinit();
    const upper_fd = c.open(session.upper.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(upper_fd >= 0);
    defer _ = c.close(upper_fd);
    inline for (.{ "a", "b" }) |name| {
        const fd = c.openat(
            upper_fd,
            name,
            c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        try std.testing.expect(fd >= 0);
        try std.testing.expectEqual(@as(isize, 1), c.write(fd, name, 1));
        _ = c.close(fd);
    }
    const first = try session.apply(lower_path, .{ .max_entries = 1 });
    try std.testing.expectEqual(@as(usize, 1), first.applied);
    try std.testing.expectEqual(@as(usize, 1), first.remaining);
    const second = try session.apply(lower_path, .{});
    try std.testing.expectEqual(@as(usize, 1), second.applied);
    try std.testing.expect(second.complete());
}

test "bounded apply completes a hard-link group together" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.mkdirat(tmp.dir.handle, "lower", @as(c.mode_t, 0o700)),
    );
    var session_buffer: [128]u8 = undefined;
    var lower_buffer: [128]u8 = undefined;
    const session_path = try std.fmt.bufPrintZ(
        &session_buffer,
        "/proc/self/fd/{d}/session",
        .{tmp.dir.handle},
    );
    const lower_path = try std.fmt.bufPrintZ(
        &lower_buffer,
        "/proc/self/fd/{d}/lower",
        .{tmp.dir.handle},
    );
    var session = try Session.open(std.testing.io, session_path);
    defer session.deinit();
    const upper_fd = c.open(session.upper.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(upper_fd >= 0);
    defer _ = c.close(upper_fd);
    const file_fd = c.openat(
        upper_fd,
        "a",
        c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    try std.testing.expect(file_fd >= 0);
    try std.testing.expectEqual(@as(isize, 1), c.write(file_fd, "x", 1));
    _ = c.close(file_fd);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.linkat(upper_fd, "a", upper_fd, "b", 0),
    );
    const result = try session.apply(lower_path, .{ .max_entries = 1 });
    try std.testing.expect(result.complete());
    const lower_fd = c.open(lower_path.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(lower_fd >= 0);
    defer _ = c.close(lower_fd);
    var a_stat: c.struct_stat = undefined;
    var b_stat: c.struct_stat = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.fstatat(
        lower_fd,
        "a",
        &a_stat,
        0,
    ));
    try std.testing.expectEqual(@as(c_int, 0), c.fstatat(
        lower_fd,
        "b",
        &b_stat,
        0,
    ));
    try std.testing.expectEqual(a_stat.st_ino, b_stat.st_ino);
}

test "apply translates whiteouts and opaque directories" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), c.mkdirat(tmp.dir.handle, "lower", @as(c.mode_t, 0o700)));
    const lower_fd = c.openat(tmp.dir.handle, "lower", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(lower_fd >= 0);
    defer _ = c.close(lower_fd);
    const victim = c.openat(lower_fd, "victim", c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c.mode_t, 0o600));
    try std.testing.expect(victim >= 0);
    _ = c.close(victim);
    try std.testing.expectEqual(@as(c_int, 0), c.mkdirat(lower_fd, "dir", @as(c.mode_t, 0o700)));
    const lower_dir = c.openat(lower_fd, "dir", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(lower_dir >= 0);
    defer _ = c.close(lower_dir);
    const old = c.openat(lower_dir, "old", c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c.mode_t, 0o600));
    try std.testing.expect(old >= 0);
    _ = c.close(old);

    var session_buffer: [128]u8 = undefined;
    var lower_buffer: [128]u8 = undefined;
    const session_path = try std.fmt.bufPrintZ(&session_buffer, "/proc/self/fd/{d}/session", .{tmp.dir.handle});
    const lower_path = try std.fmt.bufPrintZ(&lower_buffer, "/proc/self/fd/{d}/lower", .{tmp.dir.handle});
    var session = try Session.open(std.testing.io, session_path);
    defer session.deinit();
    const upper_fd = c.open(session.upper.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(upper_fd >= 0);
    defer _ = c.close(upper_fd);
    const marker = c.openat(upper_fd, "victim", c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c.mode_t, 0o600));
    try std.testing.expect(marker >= 0);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.fsetxattr(marker, "user.overlay.whiteout", "y", 1, 0),
    );
    _ = c.close(marker);
    try std.testing.expectEqual(@as(c_int, 0), c.mkdirat(upper_fd, "dir", @as(c.mode_t, 0o700)));
    const upper_dir = c.openat(upper_fd, "dir", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(upper_dir >= 0);
    defer _ = c.close(upper_dir);
    try std.testing.expectEqual(
        @as(c_int, 0),
        c.fsetxattr(upper_dir, "user.overlay.opaque", "y", 1, 0),
    );
    const fresh = c.openat(upper_dir, "new", c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c.mode_t, 0o600));
    try std.testing.expect(fresh >= 0);
    _ = c.close(fresh);

    const result = try session.apply(lower_path, .{});
    try std.testing.expect(result.complete());
    try std.testing.expectEqual(@as(c_int, -1), c.faccessat(lower_fd, "victim", c.F_OK, 0));
    const applied_dir = c.openat(lower_fd, "dir", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(applied_dir >= 0);
    defer _ = c.close(applied_dir);
    try std.testing.expectEqual(@as(c_int, -1), c.faccessat(applied_dir, "old", c.F_OK, 0));
    try std.testing.expectEqual(@as(c_int, 0), c.faccessat(applied_dir, "new", c.F_OK, 0));
}
