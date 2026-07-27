//! Low-level, policy-aware FUSE filesystem.
//!
//! Namespace inodes and open handles are pointer-backed, so callbacks do not
//! scan global tables. Only inode publication/reference accounting and shared
//! passthrough registration take the filesystem mutex. Data I/O never does.
const std = @import("std");
const fuse = @import("fuse.zig");
const overlay = @import("overlay.zig");
const policy = @import("policy.zig");
const log = @import("log.zig");

pub const c = fuse.c;
const Mode = policy.Mode;
const allocator = std.heap.c_allocator;
const root_ino: c.fuse_ino_t = 1;
const max_path = 4096;
const dir_buffer_size = 16 * 1024;

const Inode = struct {
    fd: c_int,
    path: [:0]const u8,
    device: u64 = 0,
    inode_number: u64 = 0,
    lookup_count: u64 = 1,
    open_count: std.atomic.Value(u32) = .init(0),
    backing_id: i32 = 0,
    mutex: std.Io.Mutex = .init,
    overlay_mutex: std.Io.Mutex = .init,
};

const Handle = struct {
    fd: c_int,
    overlay_fd: std.atomic.Value(c_int) = .init(-1),
    range_fd: std.atomic.Value(c_int) = .init(-1),
    ranges: std.ArrayListUnmanaged(overlay.Range) = .empty,
    range_bytes: u64 = 0,
    ranges_little_endian: bool = true,
    inode: *Inode,
    mode: std.atomic.Value(u8),
    mutex: std.Io.Mutex = .init,
};

const DirHandle = struct {
    stream: *c.DIR,
    inode: *Inode,
    mutex: std.Io.Mutex = .init,
};

pub const Fs = struct {
    io: std.Io,
    root_fd: c_int,
    session: ?*overlay.Session,
    ask_context: ?*anyopaque,
    ask_fn: ?AskFn,
    passthrough_requested: bool,
    passthrough_capable: bool = false,
    mutex: std.Io.Mutex = .init,
    root: Inode,
    inodes: std.StringHashMapUnmanaged(*Inode) = .empty,

    pub fn init(
        io: std.Io,
        root_fd: c_int,
        session: ?*overlay.Session,
        passthrough_requested: bool,
        ask_context: ?*anyopaque,
        ask_fn: ?AskFn,
    ) Fs {
        return .{
            .io = io,
            .root_fd = root_fd,
            .session = session,
            .ask_context = ask_context,
            .ask_fn = ask_fn,
            .passthrough_requested = passthrough_requested,
            .root = .{ .fd = root_fd, .path = "/" },
        };
    }

    pub fn deinit(self: *Fs) void {
        std.debug.assert(self.root.open_count.load(.acquire) == 0);
        var it = self.inodes.iterator();
        while (it.next()) |entry| {
            const node = entry.value_ptr.*;
            std.debug.assert(node.open_count.load(.acquire) == 0);
            _ = c.close(node.fd);
            allocator.free(node.path);
            allocator.destroy(node);
        }
        self.inodes.deinit(allocator);
        _ = c.close(self.root_fd);
        self.* = undefined;
    }
};

pub const Operation = enum {
    read,
    write,
    execute,
};

pub const AskRequest = struct {
    path: []const u8,
    operation: Operation,
    current: Mode,
};

pub const AskDecision = enum {
    deny,
    allow,
};

pub const AskFn = *const fn (
    context: ?*anyopaque,
    io: std.Io,
    request: AskRequest,
) anyerror!AskDecision;

fn fsFrom(req: c.fuse_req_t) *Fs {
    return @ptrCast(@alignCast(c.fuse_req_userdata(req)));
}

fn inodeFrom(fs: *Fs, ino: c.fuse_ino_t) *Inode {
    return if (ino == root_ino) &fs.root else @ptrFromInt(@as(usize, @intCast(ino)));
}

fn inoFrom(node: *Inode) c.fuse_ino_t {
    return @intCast(@intFromPtr(node));
}

fn relativePath(node: *const Inode) [*:0]const u8 {
    return if (node.path.len == 1) "." else node.path.ptr + 1;
}

fn replyErr(req: c.fuse_req_t, err: c_int) void {
    _ = c.fuse_reply_err(req, err);
}

fn childPath(parent: []const u8, name: []const u8, buf: *[max_path]u8) ?[:0]u8 {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null) return null;
    const separator: usize = @intFromBool(parent.len != 1);
    const len = parent.len + separator + name.len;
    if (len >= buf.len) return null;
    @memcpy(buf[0..parent.len], parent);
    if (separator != 0) buf[parent.len] = '/';
    @memcpy(buf[parent.len + separator .. len], name);
    buf[len] = 0;
    return buf[0..len :0];
}

fn ruleFor(path: []const u8) ?Mode {
    return policy.evaluate(path) catch |err| {
        log.err(@src(), "policy lookup failed for {s}: {t}", .{ path, err });
        return null;
    };
}

fn overlayName(path: []const u8, buf: *[33]u8) [:0]u8 {
    const id = overlay.overlayId(path);
    @memcpy(buf[0..32], &id);
    buf[32] = 0;
    return buf[0..32 :0];
}

fn openOverlay(fs: *Fs, path: []const u8, flags: c_int, register: bool) c_int {
    const session = fs.session orelse return -1;
    var id = if (register)
        session.register(path) catch |err| {
            log.err(@src(), "failed to register overlay path {s}: {t}", .{ path, err });
            return -1;
        }
    else
        overlay.overlayId(path);
    return openSessionFile(session.data_fd, &id, flags, register);
}

fn openRanges(fs: *Fs, path: []const u8, flags: c_int, register: bool) c_int {
    const session = fs.session orelse return -1;
    var id = if (register)
        session.register(path) catch |err| {
            log.err(@src(), "failed to register overlay ranges for {s}: {t}", .{ path, err });
            return -1;
        }
    else
        overlay.overlayId(path);
    const fd = openSessionFile(session.ranges_fd, &id, flags, register);
    if (fd < 0) return -1;
    if (flags & c.O_ACCMODE != c.O_RDONLY) {
        var st: c.struct_stat = undefined;
        if (c.fstat(fd, &st) != 0) {
            _ = c.close(fd);
            return -1;
        }
        const aligned = @divFloor(st.st_size, @as(c.off_t, @sizeOf(overlay.Range))) *
            @sizeOf(overlay.Range);
        if (aligned != st.st_size and c.ftruncate(fd, aligned) != 0) {
            _ = c.close(fd);
            return -1;
        }
    }
    return fd;
}

fn openSessionFile(
    directory_fd: c_int,
    id: [*:0]const u8,
    flags: c_int,
    durable_create: bool,
) c_int {
    if (!durable_create or flags & c.O_CREAT == 0)
        return c.openat(directory_fd, id, flags | c.O_NOFOLLOW | c.O_CLOEXEC, @as(c.mode_t, 0o600));

    const existing_flags = flags & ~@as(c_int, c.O_CREAT | c.O_EXCL);
    var fd = c.openat(directory_fd, id, existing_flags | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd >= 0) return fd;
    if (std.c.errno(fd) != .NOENT) return -1;

    fd = c.openat(
        directory_fd,
        id,
        flags | c.O_CREAT | c.O_EXCL | c.O_NOFOLLOW | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    if (fd < 0 and std.c.errno(fd) == .EXIST)
        return c.openat(directory_fd, id, existing_flags | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return -1;
    if (c.fsync(directory_fd) != 0) {
        _ = c.close(fd);
        return -1;
    }
    return fd;
}

fn refreshRangesLocked(handle: *Handle) bool {
    const range_fd = handle.range_fd.load(.acquire);
    if (range_fd < 0) return true;
    var st: c.struct_stat = undefined;
    if (c.fstat(range_fd, &st) != 0 or st.st_size < 0) return false;
    const valid_bytes: u64 = @divFloor(
        @as(u64, @intCast(st.st_size)),
        @sizeOf(overlay.Range),
    ) * @sizeOf(overlay.Range);
    if (valid_bytes <= handle.range_bytes) return true;
    const additional_count: usize = @intCast(
        (valid_bytes - handle.range_bytes) / @sizeOf(overlay.Range),
    );
    handle.ranges.ensureUnusedCapacity(allocator, additional_count) catch return false;
    const old_len = handle.ranges.items.len;
    handle.ranges.items.len += additional_count;
    const destination = std.mem.sliceAsBytes(handle.ranges.items[old_len..]);
    const got = c.pread(
        range_fd,
        destination.ptr,
        destination.len,
        @intCast(handle.range_bytes),
    );
    if (got != @as(isize, @intCast(destination.len))) {
        handle.ranges.items.len = old_len;
        return false;
    }
    for (handle.ranges.items[old_len..]) |*range| {
        const disk: overlay.RangeDisk = @as(*const overlay.RangeDisk, @ptrCast(range)).*;
        range.* = overlay.decodeRange(&disk, handle.ranges_little_endian);
    }
    handle.range_bytes = valid_bytes;
    return true;
}

fn appendTruncateRecord(fs: *Fs, handle: *Handle) c_int {
    handle.inode.overlay_mutex.lockUncancelable(fs.io);
    defer handle.inode.overlay_mutex.unlock(fs.io);
    if (!refreshRangesLocked(handle)) return c.EIO;
    handle.ranges.ensureUnusedCapacity(allocator, 1) catch return c.ENOMEM;
    const record: overlay.Range = .{ .offset = 0, .length = 0 };
    const disk = overlay.encodeRange(record, handle.ranges_little_endian);
    const range_fd = handle.range_fd.load(.acquire);
    if (c.write(range_fd, &disk, @sizeOf(overlay.Range)) != @sizeOf(overlay.Range))
        return c.EIO;
    handle.ranges.appendAssumeCapacity(record);
    handle.range_bytes += @sizeOf(overlay.Range);
    return 0;
}

fn logicalRangeEnd(range_fd: c_int, backing_size: u64, little_endian: bool) ?u64 {
    var st: c.struct_stat = undefined;
    if (c.fstat(range_fd, &st) != 0 or st.st_size < 0) return null;
    const valid_bytes: u64 = @divFloor(
        @as(u64, @intCast(st.st_size)),
        @sizeOf(overlay.Range),
    ) * @sizeOf(overlay.Range);
    var offset: u64 = 0;
    var records: [128]overlay.RangeDisk = undefined;
    var maximum = backing_size;
    while (offset < valid_bytes) {
        const bytes: usize = @intCast(@min(
            @as(u64, @sizeOf(@TypeOf(records))),
            valid_bytes - offset,
        ));
        const got = c.pread(range_fd, &records, bytes, @intCast(offset));
        if (got <= 0 or @rem(got, @sizeOf(overlay.Range)) != 0) return null;
        for (records[0..@intCast(@divExact(got, @sizeOf(overlay.Range)))]) |*disk| {
            const range = overlay.decodeRange(disk, little_endian);
            if (range.length == 0) {
                if (range.offset > std.math.maxInt(c.off_t)) return null;
                maximum = range.offset;
                continue;
            }
            const end = std.math.add(u64, range.offset, range.length) catch return null;
            if (end > std.math.maxInt(c.off_t)) return null;
            maximum = @max(maximum, end);
        }
        offset += @intCast(got);
    }
    return maximum;
}

fn visible(mode: Mode) bool {
    return mode.k == .visible_raw or mode.k == .visible_virtual;
}

fn loadMode(handle: *const Handle) Mode {
    return @bitCast(handle.mode.load(.acquire));
}

fn operationState(mode: Mode, operation: Operation) Mode.A {
    return switch (operation) {
        .read => mode.r,
        .write => switch (mode.w) {
            .deny => .deny,
            .ask => .ask,
            .allow, .overlay => .allow,
        },
        .execute => mode.x,
    };
}

fn allowOperation(mode: *Mode, operation: Operation) void {
    switch (operation) {
        .read => mode.r = .allow,
        .write => mode.w = .allow,
        .execute => mode.x = .allow,
    }
}

fn denyOperation(mode: *Mode, operation: Operation) void {
    switch (operation) {
        .read => mode.r = .deny,
        .write => mode.w = .deny,
        .execute => mode.x = .deny,
    }
}

/// Fast path is a single atomic byte load. Only an `ask` snapshot touches the
/// trie. A newer explicit/inherited rule is adopted before prompting, so two
/// opens do not unnecessarily issue the same request.
fn authorize(fs: *Fs, handle: *Handle, operation: Operation) bool {
    var mode = loadMode(handle);
    switch (operationState(mode, operation)) {
        .allow => return true,
        .deny, ._reserved => return false,
        .ask => {},
    }

    handle.mutex.lockUncancelable(fs.io);
    defer handle.mutex.unlock(fs.io);
    mode = loadMode(handle);
    if (operationState(mode, operation) != .ask)
        return operationState(mode, operation) == .allow;

    const refreshed = ruleFor(handle.inode.path);
    if (refreshed) |new_mode| {
        if (operationState(new_mode, operation) != .ask) {
            handle.mode.store(@bitCast(new_mode), .release);
            return operationState(new_mode, operation) == .allow;
        }
        mode = new_mode;
    }

    const ask = fs.ask_fn orelse return false;
    const decision = ask(fs.ask_context, fs.io, .{
        .path = handle.inode.path,
        .operation = operation,
        .current = mode,
    }) catch |err| {
        log.warn(@src(), "permission request failed for {s}: {t}", .{ handle.inode.path, err });
        return false;
    };
    if (decision != .allow) {
        denyOperation(&mode, operation);
        handle.mode.store(@bitCast(mode), .release);
        return false;
    }

    policy.lockUpdates();
    defer policy.unlockUpdates();
    // Another requester may have resolved this while the callback ran.
    var updated = policy.evaluateLocked(handle.inode.path) catch |err| {
        log.err(@src(), "policy recheck failed for {s}: {t}", .{ handle.inode.path, err });
        return false;
    } orelse {
        // The rule (including any inherited rule) was removed while the
        // permission request was pending. Do not resurrect stale policy.
        denyOperation(&mode, operation);
        handle.mode.store(@bitCast(mode), .release);
        return false;
    };
    if (operationState(updated, operation) == .ask) {
        allowOperation(&updated, operation);
        policy.setLocked(handle.inode.path, updated) catch |err| {
            log.err(@src(), "failed to persist permission approval for {s}: {t}", .{
                handle.inode.path,
                err,
            });
            return false;
        };
    }
    handle.mode.store(@bitCast(updated), .release);
    return operationState(updated, operation) == .allow;
}

fn statNode(fs: *Fs, node: *Inode, st: *c.struct_stat) c_int {
    const stat_rc = c.fstat(node.fd, st);
    if (stat_rc != 0) return @intFromEnum(std.c.errno(stat_rc));
    if (ruleFor(node.path)) |mode| {
        if (!visible(mode)) return c.ENOENT;
        applyPolicyStat(fs, node.path, mode, st);
        return 0;
    }
    return c.ENOENT;
}

fn applyPolicyStat(fs: *Fs, path: []const u8, mode: Mode, st: *c.struct_stat) void {
    if (mode.r == .deny) st.st_mode &= ~@as(c.mode_t, 0o444);
    if (mode.w == .deny) st.st_mode &= ~@as(c.mode_t, 0o222);
    if (mode.w == .overlay and fs.session != null)
        st.st_mode |= @as(c.mode_t, 0o222);
    if (mode.x == .deny) st.st_mode &= ~@as(c.mode_t, 0o111);
    if (mode.w == .overlay and fs.session != null) {
        const range_fd = openRanges(fs, path, c.O_RDONLY, false);
        if (range_fd >= 0) {
            if (logicalRangeEnd(
                range_fd,
                @intCast(st.st_size),
                fs.session.?.rangesAreLittleEndian(),
            )) |end|
                st.st_size = @as(c.off_t, @intCast(end));
            _ = c.close(range_fd);
        }
    }
}

fn destroyDetached(node: *Inode) void {
    _ = c.close(node.fd);
    allocator.free(node.path);
    allocator.destroy(node);
}

fn detachIfUnusedLocked(fs: *Fs, node: *Inode) bool {
    if (node == &fs.root or node.lookup_count != 0 or node.open_count.load(.acquire) != 0) return false;
    if (fs.inodes.get(node.path)) |published| {
        if (published == node) {
            _ = fs.inodes.remove(node.path);
        }
    }
    // A replaced inode is no longer in the path map, but remains alive until
    // its kernel lookup and open references both reach zero.
    return true;
}

fn initCb(userdata: ?*anyopaque, conn_opt: ?*c.struct_fuse_conn_info) callconv(.c) void {
    const fs: *Fs = @ptrCast(@alignCast(userdata orelse return));
    const conn = conn_opt orelse return;
    if (fs.passthrough_requested and c.fuse_set_feature_flag(conn, c.FUSE_CAP_PASSTHROUGH)) {
        fuse.connSetBackingDepth(conn, c.FUSE_BACKING_STACKED_UNDER);
        fs.passthrough_capable = true;
    } else if (fs.passthrough_requested) {
        log.warn(@src(), "kernel did not negotiate FUSE passthrough; using userspace I/O", .{});
    }
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_ASYNC_READ);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_AUTO_INVAL_DATA);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_READDIRPLUS);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_READDIRPLUS_AUTO);
}

fn lookupCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name_z: [*c]const u8) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = inodeFrom(fs, parent_ino);
    if (name_z == null) return replyErr(req, c.EINVAL);
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));

    var path_buf: [max_path]u8 = undefined;
    const path = childPath(parent.path, name, &path_buf) orelse
        return replyErr(req, c.ENAMETOOLONG);
    const mode = ruleFor(path) orelse return replyErr(req, c.ENOENT);
    if (!visible(mode) or mode.k != .visible_raw) return replyErr(req, c.ENOENT);

    const fd = c.openat(parent.fd, name_z, c.O_PATH | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));

    var st: c.struct_stat = undefined;
    const stat_rc = c.fstat(fd, &st);
    if (stat_rc != 0) {
        const err = @intFromEnum(std.c.errno(stat_rc));
        _ = c.close(fd);
        return replyErr(req, err);
    }
    applyPolicyStat(fs, path, mode, &st);

    const owned_path = allocator.dupeZ(u8, path) catch {
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    const candidate = allocator.create(Inode) catch {
        allocator.free(owned_path);
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    candidate.* = .{
        .fd = fd,
        .path = owned_path,
        .device = @intCast(st.st_dev),
        .inode_number = @intCast(st.st_ino),
    };

    fs.mutex.lockUncancelable(fs.io);
    const node = if (fs.inodes.get(path)) |existing| current: {
        if (existing.device == @as(u64, @intCast(st.st_dev)) and
            existing.inode_number == @as(u64, @intCast(st.st_ino)))
        {
            existing.lookup_count += 1;
            break :current existing;
        }
        // Replacement does not increase the map's entry count. Remove and
        // republish without allocation so the map key belongs to `candidate`;
        // retaining the old key would leave it dangling when `existing` dies.
        _ = fs.inodes.remove(existing.path);
        fs.inodes.putAssumeCapacity(candidate.path, candidate);
        break :current candidate;
    } else published: {
        fs.inodes.put(allocator, candidate.path, candidate) catch {
            fs.mutex.unlock(fs.io);
            destroyDetached(candidate);
            return replyErr(req, c.ENOMEM);
        };
        break :published candidate;
    };
    fs.mutex.unlock(fs.io);

    if (node != candidate) destroyDetached(candidate);

    const entry: c.struct_fuse_entry_param = .{
        .ino = inoFrom(node),
        .generation = 1,
        .attr = st,
        .attr_timeout = 0.1,
        .entry_timeout = 0.1,
    };
    _ = c.fuse_reply_entry(req, &entry);
}

fn forgetCb(req: c.fuse_req_t, ino: c.fuse_ino_t, count: u64) callconv(.c) void {
    const fs = fsFrom(req);
    const node = inodeFrom(fs, ino);
    fs.mutex.lockUncancelable(fs.io);
    node.lookup_count -|= count;
    const detached = detachIfUnusedLocked(fs, node);
    fs.mutex.unlock(fs.io);
    if (detached) destroyDetached(node);
    c.fuse_reply_none(req);
}

fn getattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = fi;
    const fs = fsFrom(req);
    var st: c.struct_stat = undefined;
    const err = statNode(fs, inodeFrom(fs, ino), &st);
    if (err != 0) return replyErr(req, err);
    _ = c.fuse_reply_attr(req, &st, 0.1);
}

fn readlinkCb(req: c.fuse_req_t, ino: c.fuse_ino_t) callconv(.c) void {
    const fs = fsFrom(req);
    const node = inodeFrom(fs, ino);
    const mode = ruleFor(node.path) orelse return replyErr(req, c.ENOENT);
    if (!visible(mode) or mode.r != .allow) return replyErr(req, c.EACCES);

    var buf: [max_path]u8 = undefined;
    const len = c.readlinkat(node.fd, "", &buf, buf.len - 1);
    if (len < 0) return replyErr(req, @intFromEnum(std.c.errno(len)));
    buf[@intCast(len)] = 0;
    _ = c.fuse_reply_readlink(req, &buf);
}

fn accessCb(req: c.fuse_req_t, ino: c.fuse_ino_t, mask: c_int) callconv(.c) void {
    const fs = fsFrom(req);
    const node = inodeFrom(fs, ino);
    const mode = ruleFor(node.path) orelse return replyErr(req, c.ENOENT);
    if (!visible(mode)) return replyErr(req, c.ENOENT);
    if (mask & c.R_OK != 0 and mode.r != .allow) return replyErr(req, c.EACCES);
    if (mask & c.W_OK != 0 and mode.w != .allow and mode.w != .overlay)
        return replyErr(req, c.EACCES);
    if (mask & c.X_OK != 0 and mode.x != .allow) return replyErr(req, c.EACCES);
    const backing_mask = if (mode.w == .overlay) mask & ~@as(c_int, c.W_OK) else mask;
    const access_rc = c.faccessat(fs.root_fd, relativePath(node), backing_mask, c.AT_EACCESS);
    if (access_rc != 0)
        return replyErr(req, @intFromEnum(std.c.errno(access_rc)));
    replyErr(req, 0);
}

fn openCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi_opt: ?*c.struct_fuse_file_info) callconv(.c) void {
    const fi = fi_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = inodeFrom(fs, ino);
    const mode_opt = ruleFor(node.path);
    var mode = mode_opt orelse return replyErr(req, c.ENOENT);
    if (!visible(mode) or mode.k != .visible_raw) return replyErr(req, c.ENOENT);

    const flags_in = fuse.FileInfo.flags(fi);
    const access_mode = flags_in & c.O_ACCMODE;
    const wants_read = access_mode != c.O_WRONLY;
    const wants_write = access_mode != c.O_RDONLY;
    const wants_truncate = flags_in & c.O_TRUNC != 0;
    const mutates_file = wants_write or wants_truncate;
    if (wants_read and mode.r == .deny) return replyErr(req, c.EACCES);
    if (mutates_file and mode.w == .deny)
        return replyErr(req, c.EACCES);
    if (mutates_file and mode.w == .overlay and fs.session == null)
        return replyErr(req, c.EROFS);
    if (wants_truncate and mode.w == .ask) {
        var permission_handle = Handle{
            .fd = -1,
            .inode = node,
            .mode = .init(@bitCast(mode)),
        };
        if (!authorize(fs, &permission_handle, .write))
            return replyErr(req, c.EACCES);
        mode = loadMode(&permission_handle);
    }

    var flags = (flags_in & ~@as(c_int, c.O_CREAT | c.O_EXCL | c.O_NOCTTY)) | c.O_CLOEXEC;
    if (mode.w == .overlay)
        flags = if (wants_read) c.O_RDONLY | c.O_CLOEXEC else c.O_PATH | c.O_CLOEXEC;
    var proc_path_buf: [64]u8 = undefined;
    const proc_path = std.fmt.bufPrintZ(&proc_path_buf, "/proc/self/fd/{d}", .{node.fd}) catch
        return replyErr(req, c.EIO);
    const fd = c.open(proc_path.ptr, flags);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));

    const handle = allocator.create(Handle) catch {
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    const overlay_fd = if (mode.w == .overlay)
        openOverlay(
            fs,
            node.path,
            if (mutates_file) c.O_RDWR | c.O_CREAT else c.O_RDONLY,
            mutates_file,
        )
    else
        -1;
    const range_fd = if (mode.w == .overlay)
        openRanges(
            fs,
            node.path,
            if (mutates_file) c.O_RDWR | c.O_CREAT | c.O_APPEND else c.O_RDONLY,
            mutates_file,
        )
    else
        -1;
    if (mutates_file and mode.w == .overlay and overlay_fd < 0) {
        if (range_fd >= 0) _ = c.close(range_fd);
        allocator.destroy(handle);
        _ = c.close(fd);
        return replyErr(req, c.EIO);
    }
    if (mutates_file and mode.w == .overlay and range_fd < 0) {
        _ = c.close(overlay_fd);
        allocator.destroy(handle);
        _ = c.close(fd);
        return replyErr(req, c.EIO);
    }
    handle.* = .{
        .fd = fd,
        .overlay_fd = .init(overlay_fd),
        .range_fd = .init(range_fd),
        .inode = node,
        .mode = .init(@bitCast(mode)),
        .ranges_little_endian = if (fs.session) |session|
            session.rangesAreLittleEndian()
        else
            true,
    };
    if (!refreshRangesLocked(handle)) {
        if (range_fd >= 0) _ = c.close(range_fd);
        if (overlay_fd >= 0) _ = c.close(overlay_fd);
        handle.ranges.deinit(allocator);
        allocator.destroy(handle);
        _ = c.close(fd);
        return replyErr(req, c.EIO);
    }
    if (mode.w == .overlay and wants_truncate) {
        const truncate_err = appendTruncateRecord(fs, handle);
        if (truncate_err != 0) {
            if (range_fd >= 0) _ = c.close(range_fd);
            if (overlay_fd >= 0) _ = c.close(overlay_fd);
            handle.ranges.deinit(allocator);
            allocator.destroy(handle);
            _ = c.close(fd);
            return replyErr(req, truncate_err);
        }
    }

    node.mutex.lockUncancelable(fs.io);
    if (fs.passthrough_capable and policy.canPassthroughMode(mode)) {
        if (node.backing_id == 0) {
            node.backing_id = c.fuse_passthrough_open(req, fd);
            if (node.backing_id == 0)
                log.warn(@src(), "passthrough registration failed for {s}", .{node.path});
        }
        fuse.FileInfo.setBackingId(fi, node.backing_id);
    }
    fs.mutex.lockUncancelable(fs.io);
    _ = node.open_count.fetchAdd(1, .release);
    fs.mutex.unlock(fs.io);
    node.mutex.unlock(fs.io);

    fuse.FileInfo.setFh(fi, @intFromPtr(handle));
    fuse.FileInfo.setKeepCache(fi, @intFromBool(fuse.FileInfo.backingId(fi) == 0));
    fuse.FileInfo.setNoflush(fi, @intFromBool(!mutates_file));
    _ = c.fuse_reply_open(req, fi);
}

fn readCb(
    req: c.fuse_req_t,
    ino: c.fuse_ino_t,
    size: usize,
    off: c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) void {
    _ = ino;
    const info = fi orelse return replyErr(req, c.EBADF);
    const handle: *Handle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const fs = fsFrom(req);
    if (!authorize(fs, handle, .read)) return replyErr(req, c.EACCES);
    const mode = loadMode(handle);
    if (mode.w == .overlay and handle.overlay_fd.load(.acquire) >= 0)
        return readOverlay(req, handle, size, off);
    var vec: c.struct_fuse_bufvec = .{
        .count = 1,
        .idx = 0,
        .off = 0,
        .buf = .{.{
            .size = size,
            .flags = c.FUSE_BUF_IS_FD | c.FUSE_BUF_FD_SEEK | c.FUSE_BUF_FD_RETRY,
            .mem = null,
            .fd = handle.fd,
            .pos = off,
            .mem_size = 0,
        }},
    };
    _ = c.fuse_reply_data(req, &vec, 0);
}

fn readOverlay(req: c.fuse_req_t, handle: *Handle, size: usize, off: c.off_t) void {
    if (off < 0) return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    handle.mutex.lockUncancelable(fs.io);
    defer handle.mutex.unlock(fs.io);
    if (!refreshRangesLocked(handle)) return replyErr(req, c.EIO);

    var backing_stat: c.struct_stat = undefined;
    const stat_rc = c.fstat(handle.fd, &backing_stat);
    if (stat_rc != 0) return replyErr(req, @intFromEnum(std.c.errno(stat_rc)));
    const overlay_fd = handle.overlay_fd.load(.acquire);
    var logical_size: u64 = @intCast(backing_stat.st_size);
    var backing_limit = logical_size;
    var active_range_start: usize = 0;
    for (handle.ranges.items, 0..) |range, index| {
        if (range.length == 0) {
            if (range.offset > std.math.maxInt(c.off_t)) return replyErr(req, c.EIO);
            logical_size = range.offset;
            backing_limit = @min(backing_limit, range.offset);
            active_range_start = index + 1;
            continue;
        }
        const end = std.math.add(u64, range.offset, range.length) catch
            return replyErr(req, c.EIO);
        if (end > std.math.maxInt(c.off_t)) return replyErr(req, c.EIO);
        logical_size = @max(logical_size, end);
    }
    const offset: u64 = @intCast(off);
    if (offset >= logical_size) {
        _ = c.fuse_reply_buf(req, null, 0);
        return;
    }
    const reply_len: usize = @intCast(@min(@as(u64, size), logical_size - offset));
    const reply = allocator.alloc(u8, reply_len) catch return replyErr(req, c.ENOMEM);
    defer allocator.free(reply);
    @memset(reply, 0);

    const backing_len: usize = @intCast(@min(@as(u64, reply.len), backing_limit -| offset));
    if (backing_len != 0) {
        const backing_read = c.pread(handle.fd, reply.ptr, backing_len, off);
        if (backing_read < 0) return replyErr(req, @intFromEnum(std.c.errno(backing_read)));
    }

    const request_end = offset + reply_len;
    for (handle.ranges.items[active_range_start..]) |range| {
        if (range.length == 0 or range.offset >= request_end) continue;
        const range_end = std.math.add(u64, range.offset, range.length) catch
            return replyErr(req, c.EIO);
        if (range_end <= offset) continue;
        const start = @max(range.offset, offset);
        const end = @min(range_end, request_end);
        if (start > std.math.maxInt(c.off_t)) return replyErr(req, c.EIO);
        const destination = reply[@intCast(start - offset)..@intCast(end - offset)];
        const got = c.pread(overlay_fd, destination.ptr, destination.len, @intCast(start));
        if (got != @as(isize, @intCast(destination.len)))
            return replyErr(req, if (got < 0) @intFromEnum(std.c.errno(got)) else c.EIO);
    }
    _ = c.fuse_reply_buf(req, reply.ptr, reply.len);
}

fn writeCb(
    req: c.fuse_req_t,
    ino: c.fuse_ino_t,
    buf: [*c]const u8,
    size: usize,
    off: c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) void {
    _ = ino;
    if (buf == null) return replyErr(req, c.EINVAL);
    const info = fi orelse return replyErr(req, c.EBADF);
    const handle: *Handle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const fs = fsFrom(req);
    if (!authorize(fs, handle, .write)) return replyErr(req, c.EACCES);
    const mode = loadMode(handle);
    if (mode.w == .overlay)
        return writeOverlay(req, fs, handle, buf, size, off);
    const written = c.pwrite(handle.fd, buf, size, off);
    if (written < 0) return replyErr(req, @intFromEnum(std.c.errno(written)));
    _ = c.fuse_reply_write(req, @intCast(written));
}

fn writeOverlay(
    req: c.fuse_req_t,
    fs: *Fs,
    handle: *Handle,
    buf: [*c]const u8,
    size: usize,
    off: c.off_t,
) void {
    if (off < 0) return replyErr(req, c.EINVAL);
    handle.mutex.lockUncancelable(fs.io);
    defer handle.mutex.unlock(fs.io);

    var overlay_fd = handle.overlay_fd.load(.acquire);
    var range_fd = handle.range_fd.load(.acquire);
    if (overlay_fd < 0 or range_fd < 0) {
        if (overlay_fd < 0) {
            overlay_fd = openOverlay(fs, handle.inode.path, c.O_RDWR | c.O_CREAT, true);
            if (overlay_fd < 0) return replyErr(req, c.EIO);
            handle.overlay_fd.store(overlay_fd, .release);
        }
        if (range_fd < 0) {
            range_fd = openRanges(
                fs,
                handle.inode.path,
                c.O_RDWR | c.O_CREAT | c.O_APPEND,
                true,
            );
            if (range_fd < 0) return replyErr(req, c.EIO);
            handle.range_fd.store(range_fd, .release);
        }
    }
    // Exact range records must not interleave across separate opens of the
    // same inode. This lock is overlay-only; raw/passthrough I/O never pays it.
    handle.inode.overlay_mutex.lockUncancelable(fs.io);
    defer handle.inode.overlay_mutex.unlock(fs.io);
    if (!refreshRangesLocked(handle)) return replyErr(req, c.EIO);
    handle.ranges.ensureUnusedCapacity(allocator, 1) catch
        return replyErr(req, c.ENOMEM);

    const written = c.pwrite(overlay_fd, buf, size, off);
    if (written < 0) return replyErr(req, @intFromEnum(std.c.errno(written)));
    if (written != 0) {
        const record = overlay.Range{
            .offset = @intCast(off),
            .length = @intCast(written),
        };
        const disk = overlay.encodeRange(record, handle.ranges_little_endian);
        if (c.write(range_fd, &disk, @sizeOf(overlay.Range)) != @sizeOf(overlay.Range)) {
            return replyErr(req, c.EIO);
        }
        handle.ranges.appendAssumeCapacity(record);
        handle.range_bytes += @sizeOf(overlay.Range);
    }
    _ = c.fuse_reply_write(req, @intCast(written));
}

fn flushCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const info = fi orelse return replyErr(req, c.EBADF);
    const handle: *Handle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const overlay_fd = handle.overlay_fd.load(.acquire);
    const target_fd = if (overlay_fd >= 0) overlay_fd else handle.fd;
    const duplicate = c.dup(target_fd);
    if (duplicate < 0) return replyErr(req, @intFromEnum(std.c.errno(duplicate)));
    const close_rc = c.close(duplicate);
    if (close_rc != 0) return replyErr(req, @intFromEnum(std.c.errno(close_rc)));
    const range_fd = handle.range_fd.load(.acquire);
    if (range_fd >= 0) {
        const range_duplicate = c.dup(range_fd);
        if (range_duplicate < 0)
            return replyErr(req, @intFromEnum(std.c.errno(range_duplicate)));
        const range_close_rc = c.close(range_duplicate);
        if (range_close_rc != 0)
            return replyErr(req, @intFromEnum(std.c.errno(range_close_rc)));
    }
    replyErr(req, 0);
}

fn fsyncCb(req: c.fuse_req_t, ino: c.fuse_ino_t, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const info = fi orelse return replyErr(req, c.EBADF);
    const handle: *Handle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const overlay_fd = handle.overlay_fd.load(.acquire);
    const target_fd = if (overlay_fd >= 0) overlay_fd else handle.fd;
    const rc = if (datasync != 0) c.fdatasync(target_fd) else c.fsync(target_fd);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    const range_fd = handle.range_fd.load(.acquire);
    if (range_fd >= 0) {
        const range_rc = if (datasync != 0) c.fdatasync(range_fd) else c.fsync(range_fd);
        if (range_rc != 0) return replyErr(req, @intFromEnum(std.c.errno(range_rc)));
    }
    replyErr(req, 0);
}

fn releaseCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const info = fi orelse return replyErr(req, 0);
    const handle: *Handle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const fs = fsFrom(req);
    const node = handle.inode;

    const backing_close_rc = c.close(handle.fd);
    if (backing_close_rc != 0)
        log.warn(@src(), "failed to close backing handle for {s}: errno {d}", .{
            node.path,
            @intFromEnum(std.c.errno(backing_close_rc)),
        });
    const overlay_fd = handle.overlay_fd.load(.acquire);
    if (overlay_fd >= 0) {
        const close_rc = c.close(overlay_fd);
        if (close_rc != 0)
            log.warn(@src(), "failed to close overlay handle for {s}: errno {d}", .{
                node.path,
                @intFromEnum(std.c.errno(close_rc)),
            });
    }
    const range_fd = handle.range_fd.load(.acquire);
    if (range_fd >= 0) {
        const close_rc = c.close(range_fd);
        if (close_rc != 0)
            log.warn(@src(), "failed to close overlay journal for {s}: errno {d}", .{
                node.path,
                @intFromEnum(std.c.errno(close_rc)),
            });
    }
    handle.ranges.deinit(allocator);
    allocator.destroy(handle);

    node.mutex.lockUncancelable(fs.io);
    // Keep the open reference published while closing the shared passthrough
    // registration. FORGET only takes fs.mutex, so decrementing first would
    // let it free `node` while this callback still accesses backing_id.
    if (node.open_count.load(.acquire) == 1 and node.backing_id != 0) {
        if (c.fuse_passthrough_close(req, node.backing_id) < 0)
            log.warn(@src(), "failed to close passthrough id {d} for {s}", .{ node.backing_id, node.path });
        node.backing_id = 0;
    }
    fs.mutex.lockUncancelable(fs.io);
    const previous = node.open_count.fetchSub(1, .acq_rel);
    std.debug.assert(previous != 0);
    const detached = detachIfUnusedLocked(fs, node);
    // Keep the inode-map lock held until this callback no longer touches the
    // inode. FORGET only takes fs.mutex and may destroy a detached inode as
    // soon as that lock is released.
    node.mutex.unlock(fs.io);
    fs.mutex.unlock(fs.io);

    if (detached) destroyDetached(node);
    replyErr(req, 0);
}

fn opendirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi_opt: ?*c.struct_fuse_file_info) callconv(.c) void {
    const fi = fi_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = inodeFrom(fs, ino);
    const mode = ruleFor(node.path) orelse return replyErr(req, c.ENOENT);
    if (!visible(mode) or mode.r != .allow) return replyErr(req, c.EACCES);

    var proc_path_buf: [64]u8 = undefined;
    const proc_path = std.fmt.bufPrintZ(&proc_path_buf, "/proc/self/fd/{d}", .{node.fd}) catch
        return replyErr(req, c.EIO);
    const fd = c.open(proc_path.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    const stream = c.fdopendir(fd) orelse {
        // A null pointer carries no integer return code. std.c.errno still
        // provides the libc errno conversion when given the documented -1
        // failure sentinel.
        const err = @intFromEnum(std.c.errno(@as(c_int, -1)));
        _ = c.close(fd);
        return replyErr(req, err);
    };
    const handle = allocator.create(DirHandle) catch {
        _ = c.closedir(stream);
        return replyErr(req, c.ENOMEM);
    };
    handle.* = .{ .stream = stream, .inode = node };
    fs.mutex.lockUncancelable(fs.io);
    _ = node.open_count.fetchAdd(1, .release);
    fs.mutex.unlock(fs.io);
    fuse.FileInfo.setFh(fi, @intFromPtr(handle));
    // Policy updates must become visible without reopening the directory.
    fuse.FileInfo.setCacheReaddir(fi, 0);
    _ = c.fuse_reply_open(req, fi);
}

fn direntMode(kind: u8) c.mode_t {
    return switch (kind) {
        c.DT_DIR => c.S_IFDIR,
        c.DT_LNK => c.S_IFLNK,
        c.DT_FIFO => c.S_IFIFO,
        c.DT_SOCK => c.S_IFSOCK,
        c.DT_CHR => c.S_IFCHR,
        c.DT_BLK => c.S_IFBLK,
        else => c.S_IFREG,
    };
}

fn readdirCb(
    req: c.fuse_req_t,
    ino: c.fuse_ino_t,
    requested_size: usize,
    off: c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) void {
    _ = ino;
    const fs = fsFrom(req);
    const info = fi orelse return replyErr(req, c.EBADF);
    const handle: *DirHandle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const capacity = @min(requested_size, dir_buffer_size);
    var reply: [dir_buffer_size]u8 = undefined;
    var used: usize = 0;

    handle.mutex.lockUncancelable(fs.io);
    defer handle.mutex.unlock(fs.io);
    c.seekdir(handle.stream, @intCast(off));
    while (used < capacity) {
        const entry = c.readdir(handle.stream) orelse break;
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
        const special = std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..");
        if (!special) {
            var path_buf: [max_path]u8 = undefined;
            const path = childPath(handle.inode.path, name, &path_buf) orelse continue;
            const mode = ruleFor(path) orelse continue;
            if (!visible(mode)) continue;
        }

        var st = std.mem.zeroes(c.struct_stat);
        st.st_ino = entry.*.d_ino;
        st.st_mode = direntMode(entry.*.d_type);
        const next = c.telldir(handle.stream);
        const needed = c.fuse_add_direntry(
            req,
            reply[used..].ptr,
            capacity - used,
            @ptrCast(&entry.*.d_name),
            &st,
            @intCast(next),
        );
        if (needed > capacity - used) break;
        used += needed;
    }
    _ = c.fuse_reply_buf(req, &reply, used);
}

fn releasedirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const info = fi orelse return replyErr(req, 0);
    const handle: *DirHandle = @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
    const fs = fsFrom(req);
    const node = handle.inode;
    _ = c.closedir(handle.stream);
    allocator.destroy(handle);

    fs.mutex.lockUncancelable(fs.io);
    const previous = node.open_count.fetchSub(1, .acq_rel);
    std.debug.assert(previous != 0);
    const detached = detachIfUnusedLocked(fs, node);
    fs.mutex.unlock(fs.io);
    if (detached) destroyDetached(node);
    replyErr(req, 0);
}

fn statfsCb(req: c.fuse_req_t, ino: c.fuse_ino_t) callconv(.c) void {
    _ = ino;
    var st: c.struct_statvfs = undefined;
    const rc = c.fstatvfs(fsFrom(req).root_fd, &st);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    _ = c.fuse_reply_statfs(req, &st);
}

fn denyCb(req: c.fuse_req_t) void {
    replyErr(req, c.EPERM);
}

fn mutationPolicy(parent: *Inode, name_z: [*c]const u8) c_int {
    if (name_z == null) return c.EINVAL;
    const parent_mode = ruleFor(parent.path) orelse return c.ENOENT;
    if (parent_mode.w == .overlay) return c.EROFS;
    if (parent_mode.w != .allow) return c.EACCES;

    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    var path_buf: [max_path]u8 = undefined;
    const path = childPath(parent.path, name, &path_buf) orelse return c.ENAMETOOLONG;
    const child_mode = ruleFor(path) orelse return c.ENOENT;
    if (!visible(child_mode)) return c.EACCES;
    if (child_mode.w == .overlay) return c.EROFS;
    return if (child_mode.w == .allow) 0 else c.EACCES;
}

fn mknodCb(
    req: c.fuse_req_t,
    parent_ino: c.fuse_ino_t,
    name: [*c]const u8,
    mode: c.mode_t,
    rdev: c.dev_t,
) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = inodeFrom(fs, parent_ino);
    const policy_err = mutationPolicy(parent, name);
    if (policy_err != 0) return replyErr(req, policy_err);
    const kind = mode & c.S_IFMT;
    if (kind != 0 and kind != c.S_IFREG and kind != c.S_IFIFO)
        return replyErr(req, c.EPERM);
    const rc = c.mknodat(parent.fd, name, mode, rdev);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    lookupCb(req, parent_ino, name);
}

fn mkdirCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8, mode: c.mode_t) callconv(.c) void {
    const fs = fsFrom(req);
    const parent_node = inodeFrom(fs, parent);
    const policy_err = mutationPolicy(parent_node, name);
    if (policy_err != 0) return replyErr(req, policy_err);
    const rc = c.mkdirat(parent_node.fd, name, mode);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    lookupCb(req, parent, name);
}
fn unlinkCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8) callconv(.c) void {
    const fs = fsFrom(req);
    const parent_node = inodeFrom(fs, parent);
    const policy_err = mutationPolicy(parent_node, name);
    if (policy_err != 0) return replyErr(req, policy_err);
    const rc = c.unlinkat(parent_node.fd, name, 0);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    replyErr(req, 0);
}
fn rmdirCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8) callconv(.c) void {
    const fs = fsFrom(req);
    const parent_node = inodeFrom(fs, parent);
    const policy_err = mutationPolicy(parent_node, name);
    if (policy_err != 0) return replyErr(req, policy_err);
    const rc = c.unlinkat(parent_node.fd, name, c.AT_REMOVEDIR);
    if (rc != 0)
        return replyErr(req, @intFromEnum(std.c.errno(rc)));
    replyErr(req, 0);
}
fn renameCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8, newparent: c.fuse_ino_t, newname: [*c]const u8, flags: c_uint) callconv(.c) void {
    _ = parent;
    _ = name;
    _ = newparent;
    _ = newname;
    _ = flags;
    denyCb(req);
}

pub const ops = std.mem.zeroInit(c.struct_fuse_lowlevel_ops, .{
    .init = initCb,
    .lookup = lookupCb,
    .forget = forgetCb,
    .getattr = getattrCb,
    .readlink = readlinkCb,
    .access = accessCb,
    .open = openCb,
    .read = readCb,
    .write = writeCb,
    .flush = flushCb,
    .fsync = fsyncCb,
    .release = releaseCb,
    .opendir = opendirCb,
    .readdir = readdirCb,
    .releasedir = releasedirCb,
    .statfs = statfsCb,
    .mknod = mknodCb,
    .mkdir = mkdirCb,
    .unlink = unlinkCb,
    .rmdir = rmdirCb,
    .rename = renameCb,
});

test "child path joins root without duplicate slash" {
    var buf: [max_path]u8 = undefined;
    try std.testing.expectEqualStrings("/etc", childPath("/", "etc", &buf).?);
}

test "child path joins nested components" {
    var buf: [max_path]u8 = undefined;
    try std.testing.expectEqualStrings("/usr/bin", childPath("/usr", "bin", &buf).?);
}

test "child path rejects separators and overflow" {
    var buf: [max_path]u8 = undefined;
    try std.testing.expect(childPath("/", "a/b", &buf) == null);
    var long: [max_path]u8 = undefined;
    @memset(&long, 'x');
    try std.testing.expect(childPath("/", &long, &buf) == null);
}

test "overlay names are stable and path-sensitive" {
    var a: [33]u8 = undefined;
    var b: [33]u8 = undefined;
    try std.testing.expectEqualStrings(overlayName("/a", &a), overlayName("/a", &b));
    try std.testing.expect(!std.mem.eql(u8, overlayName("/a", &a), overlayName("/b", &b)));
}

test "overlay logical size honors truncation and rejects overflowing ranges" {
    const fd = try std.posix.memfd_create("fs-logical-range-test", 0);
    defer _ = c.close(fd);
    const ranges = [_]overlay.Range{
        .{ .offset = 10, .length = 5 },
        .{ .offset = 3, .length = 0 },
        .{ .offset = 5, .length = 2 },
    };
    for (ranges) |range| {
        const disk = overlay.encodeRange(range, true);
        try std.testing.expectEqual(
            @as(isize, @sizeOf(overlay.Range)),
            c.write(fd, &disk, disk.len),
        );
    }
    try std.testing.expectEqual(@as(?u64, 7), logicalRangeEnd(fd, 100, true));

    try std.testing.expectEqual(@as(c_int, 0), c.ftruncate(fd, 0));
    const invalid = overlay.encodeRange(.{
        .offset = std.math.maxInt(u64),
        .length = 1,
    }, true);
    try std.testing.expectEqual(
        @as(isize, @sizeOf(overlay.Range)),
        c.write(fd, &invalid, invalid.len),
    );
    try std.testing.expectEqual(@as(?u64, null), logicalRangeEnd(fd, 0, true));
}

test "ask approval updates explicit policy and handle snapshot" {
    const trie_fd = try std.posix.memfd_create("fs-ask-test", 0);
    try policy.init(std.testing.io, trie_fd);
    defer policy.deinit();

    const ask_mode = Mode{
        .k = .visible_raw,
        .r = .ask,
        .w = .deny,
        .x = .allow,
    };
    try policy.set("/file", ask_mode);

    const Callback = struct {
        fn ask(context: ?*anyopaque, _: std.Io, request: AskRequest) !AskDecision {
            const count: *usize = @ptrCast(@alignCast(context.?));
            count.* += 1;
            try std.testing.expectEqual(Operation.read, request.operation);
            return .allow;
        }
    };
    var count: usize = 0;
    var fs = Fs.init(
        std.testing.io,
        -1,
        null,
        false,
        &count,
        Callback.ask,
    );
    var inode = Inode{ .fd = -1, .path = "/file" };
    var handle = Handle{
        .fd = -1,
        .inode = &inode,
        .mode = .init(@bitCast(ask_mode)),
    };

    try std.testing.expect(authorize(&fs, &handle, .read));
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(Mode.A.allow, loadMode(&handle).r);
    try std.testing.expectEqual(Mode.A.allow, (try policy.get("/file")).?.r);

    // The second operation is the atomic snapshot fast path.
    try std.testing.expect(authorize(&fs, &handle, .read));
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "ask denial is cached in the handle snapshot" {
    const trie_fd = try std.posix.memfd_create("fs-ask-denial-test", 0);
    try policy.init(std.testing.io, trie_fd);
    defer policy.deinit();
    const ask_mode = Mode{
        .k = .visible_raw,
        .r = .ask,
        .w = .deny,
        .x = .allow,
    };
    try policy.set("/file", ask_mode);
    const Callback = struct {
        fn ask(context: ?*anyopaque, _: std.Io, _: AskRequest) !AskDecision {
            const count: *usize = @ptrCast(@alignCast(context.?));
            count.* += 1;
            return .deny;
        }
    };
    var count: usize = 0;
    var fs = Fs.init(std.testing.io, -1, null, false, &count, Callback.ask);
    var inode = Inode{ .fd = -1, .path = "/file" };
    var handle = Handle{
        .fd = -1,
        .inode = &inode,
        .mode = .init(@bitCast(ask_mode)),
    };
    try std.testing.expect(!authorize(&fs, &handle, .read));
    try std.testing.expect(!authorize(&fs, &handle, .read));
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(Mode.A.deny, loadMode(&handle).r);
}

test "ask approval does not resurrect a rule removed while pending" {
    const trie_fd = try std.posix.memfd_create("fs-ask-removal-test", 0);
    try policy.init(std.testing.io, trie_fd);
    defer policy.deinit();
    const ask_mode = Mode{
        .k = .visible_raw,
        .r = .ask,
        .w = .deny,
        .x = .allow,
    };
    try policy.set("/file", ask_mode);
    const Callback = struct {
        fn ask(_: ?*anyopaque, _: std.Io, request: AskRequest) !AskDecision {
            try std.testing.expectEqualStrings("/file", request.path);
            try policy.remove("/file");
            return .allow;
        }
    };
    var fs = Fs.init(std.testing.io, -1, null, false, null, Callback.ask);
    var inode = Inode{ .fd = -1, .path = "/file" };
    var handle = Handle{
        .fd = -1,
        .inode = &inode,
        .mode = .init(@bitCast(ask_mode)),
    };

    try std.testing.expect(!authorize(&fs, &handle, .read));
    try std.testing.expectEqual(@as(?Mode, null), try policy.get("/file"));
    try std.testing.expectEqual(Mode.A.deny, loadMode(&handle).r);
}

test "an open directory reference keeps a forgotten inode alive" {
    var fs = Fs.init(std.testing.io, -1, null, false, null, null);
    defer fs.inodes.deinit(allocator);

    const node = try allocator.create(Inode);
    errdefer allocator.destroy(node);
    const path = try allocator.dupeZ(u8, "/directory");
    errdefer allocator.free(path);
    node.* = .{
        .fd = -1,
        .path = path,
        .lookup_count = 1,
        .open_count = .init(1),
    };
    try fs.inodes.put(allocator, node.path, node);

    fs.mutex.lockUncancelable(fs.io);
    node.lookup_count = 0;
    try std.testing.expect(!detachIfUnusedLocked(&fs, node));
    fs.mutex.unlock(fs.io);

    fs.mutex.lockUncancelable(fs.io);
    const previous = node.open_count.fetchSub(1, .acq_rel);
    try std.testing.expectEqual(@as(u32, 1), previous);
    const detached = detachIfUnusedLocked(&fs, node);
    fs.mutex.unlock(fs.io);
    try std.testing.expect(detached);
    destroyDetached(node);
}

test "a replaced inode is reclaimed only after all references drain" {
    var fs = Fs.init(std.testing.io, -1, null, false, null, null);
    defer fs.inodes.deinit(allocator);
    const old = try allocator.create(Inode);
    const old_path = try allocator.dupeZ(u8, "/file");
    old.* = .{
        .fd = -1,
        .path = old_path,
        .lookup_count = 0,
        .open_count = .init(1),
    };
    const replacement = try allocator.create(Inode);
    const replacement_path = try allocator.dupeZ(u8, "/file");
    replacement.* = .{ .fd = -1, .path = replacement_path };
    try fs.inodes.put(allocator, replacement.path, replacement);

    fs.mutex.lockUncancelable(fs.io);
    try std.testing.expect(!detachIfUnusedLocked(&fs, old));
    _ = old.open_count.fetchSub(1, .acq_rel);
    try std.testing.expect(detachIfUnusedLocked(&fs, old));
    fs.mutex.unlock(fs.io);
    destroyDetached(old);

    fs.mutex.lockUncancelable(fs.io);
    replacement.lookup_count = 0;
    try std.testing.expect(detachIfUnusedLocked(&fs, replacement));
    fs.mutex.unlock(fs.io);
    destroyDetached(replacement);
}
