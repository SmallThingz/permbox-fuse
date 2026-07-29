//! Thin low-level FUSE policy layer over a private OverlayFS mount.
const std = @import("std");
const fuse = @import("fuse.zig");
const policy = @import("policy.zig");
const log = @import("log.zig");

pub const c = fuse.c;
pub const Access = policy.Access;
const allocator = std.heap.c_allocator;
const root_ino: c.fuse_ino_t = 1;
const max_path = 4096;
const dir_buffer_size = 64 * 1024;
const internal_trash = ".permfuse-internal-trash";
var trash_counter: std.atomic.Value(u64) = .init(0);

const Inode = struct {
    fd: c_int,
    path: [:0]const u8,
    dev: u64,
    ino: u64,
    lookup_count: u64 = 1,
    open_count: u32 = 0,
};

const Handle = struct {
    fd: c_int,
    inode: *Inode,
    access: Access,
    backing_id: i32 = 0,
};

const DirHandle = struct {
    stream: *c.DIR,
    inode: *Inode,
    access: Access,
    mutex: std.Io.Mutex = .init,
};

pub const Operation = enum {
    metadata,
    read,
    write,
    create,
};

pub const AskRequest = struct {
    path: []const u8,
    operation: Operation,
};

pub const AskFn = *const fn (
    context: ?*anyopaque,
    io: std.Io,
    request: AskRequest,
) anyerror!Access;

pub const Fs = struct {
    io: std.Io,
    root_fd: c_int,
    ask_context: ?*anyopaque,
    ask_fn: ?AskFn,
    passthrough_requested: bool,
    passthrough_capable: bool = false,
    mutex: std.Io.Mutex = .init,
    ask_mutexes: [64]std.Io.Mutex = [_]std.Io.Mutex{.init} ** 64,
    root: Inode,
    inodes: std.StringHashMapUnmanaged(*Inode) = .empty,

    pub fn init(
        io: std.Io,
        root_fd: c_int,
        passthrough: bool,
        ask_context: ?*anyopaque,
        ask_fn: ?AskFn,
    ) !Fs {
        var st: c.struct_stat = undefined;
        const rc = c.fstat(root_fd, &st);
        if (rc != 0) return error.StatMergedRootFailed;
        return .{
            .io = io,
            .root_fd = root_fd,
            .ask_context = ask_context,
            .ask_fn = ask_fn,
            .passthrough_requested = passthrough,
            .root = .{
                .fd = root_fd,
                .path = "/",
                .dev = @intCast(st.st_dev),
                .ino = @intCast(st.st_ino),
            },
        };
    }

    pub fn deinit(self: *Fs) void {
        std.debug.assert(self.root.open_count == 0);
        var iterator = self.inodes.iterator();
        while (iterator.next()) |entry| destroyNode(entry.value_ptr.*);
        self.inodes.deinit(allocator);
        _ = c.close(self.root_fd);
        self.* = undefined;
    }
};

fn fsFrom(req: c.fuse_req_t) *Fs {
    return @ptrCast(@alignCast(c.fuse_req_userdata(req)));
}

fn nodeFrom(fs: *Fs, ino: c.fuse_ino_t) *Inode {
    return if (ino == root_ino) &fs.root else @ptrFromInt(@as(usize, @intCast(ino)));
}

fn nodeNumber(node: *Inode) c.fuse_ino_t {
    return @intCast(@intFromPtr(node));
}

fn replyErr(req: c.fuse_req_t, err: c_int) void {
    _ = c.fuse_reply_err(req, err);
}

fn childPath(parent: []const u8, name: []const u8, buffer: *[max_path]u8) ?[:0]u8 {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
        return null;
    const slash: usize = @intFromBool(parent.len != 1);
    const len = parent.len + slash + name.len;
    if (len >= buffer.len) return null;
    @memcpy(buffer[0..parent.len], parent);
    if (slash != 0) buffer[parent.len] = '/';
    @memcpy(buffer[parent.len + slash .. len], name);
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn resolve(fs: *Fs, path: []const u8, operation: Operation) ?Access {
    var access = policy.evaluate(path) catch |err| {
        log.err(@src(), "policy evaluation failed; path={s}, error={t}", .{ path, err });
        return null;
    } orelse return .whiteout;
    if (access != .ask) return access;

    const stripe = std.hash.Wyhash.hash(0, path) % fs.ask_mutexes.len;
    fs.ask_mutexes[stripe].lockUncancelable(fs.io);
    defer fs.ask_mutexes[stripe].unlock(fs.io);
    access = (policy.evaluate(path) catch return null) orelse .whiteout;
    if (access != .ask) return access;

    const callback = fs.ask_fn orelse return .whiteout;
    const decision = callback(fs.ask_context, fs.io, .{
        .path = path,
        .operation = operation,
    }) catch |err| {
        log.warn(@src(), "permission prompt failed; path={s}, error={t}", .{ path, err });
        return null;
    };
    if (decision == .ask) {
        log.warn(@src(), "permission prompt returned unresolved state; path={s}", .{path});
        return null;
    }
    policy.lockUpdates();
    defer policy.unlockUpdates();
    const current = (policy.evaluateLocked(path) catch return null) orelse .whiteout;
    if (current != .ask) return current;
    policy.setLocked(path, decision) catch |err| {
        log.err(@src(), "failed to persist permission decision; path={s}, error={t}", .{ path, err });
        return null;
    };
    return decision;
}

fn writable(fs: *Fs, path: []const u8, operation: Operation) bool {
    return resolve(fs, path, operation) == .rw;
}

fn visible(fs: *Fs, path: []const u8, operation: Operation) ?Access {
    const access = resolve(fs, path, operation) orelse return null;
    return if (access == .whiteout) null else access;
}

fn procPath(fd: c_int, buffer: *[64]u8) ?[:0]u8 {
    return std.fmt.bufPrintZ(buffer, "/proc/self/fd/{d}", .{fd}) catch null;
}

fn openNode(node: *Inode, flags: c_int) c_int {
    var buffer: [64]u8 = undefined;
    const path = procPath(node.fd, &buffer) orelse return -1;
    return c.open(path.ptr, flags | c.O_CLOEXEC);
}

fn statNode(node: *Inode, st: *c.struct_stat) c_int {
    const rc = c.fstat(node.fd, st);
    return if (rc == 0) 0 else @intFromEnum(std.c.errno(rc));
}

fn destroyNode(node: *Inode) void {
    _ = c.close(node.fd);
    allocator.free(node.path);
    allocator.destroy(node);
}

fn detachLocked(fs: *Fs, node: *Inode) bool {
    if (node == &fs.root or node.lookup_count != 0 or node.open_count != 0) return false;
    if (fs.inodes.get(node.path)) |published| {
        if (published == node) _ = fs.inodes.remove(node.path);
    }
    return true;
}

fn publish(
    fs: *Fs,
    path: []const u8,
    fd: c_int,
    st: *const c.struct_stat,
) ?*Inode {
    const owned_path = allocator.dupeZ(u8, path) catch return null;
    errdefer allocator.free(owned_path);
    const candidate = allocator.create(Inode) catch return null;
    errdefer allocator.destroy(candidate);
    candidate.* = .{
        .fd = fd,
        .path = owned_path,
        .dev = @intCast(st.st_dev),
        .ino = @intCast(st.st_ino),
    };

    fs.mutex.lockUncancelable(fs.io);
    if (fs.inodes.get(path)) |existing| {
        if (existing.dev == candidate.dev and existing.ino == candidate.ino) {
            existing.lookup_count += 1;
            fs.mutex.unlock(fs.io);
            _ = c.close(fd);
            allocator.free(owned_path);
            allocator.destroy(candidate);
            return existing;
        }
        _ = fs.inodes.remove(existing.path);
    }
    fs.inodes.put(allocator, candidate.path, candidate) catch {
        fs.mutex.unlock(fs.io);
        return null;
    };
    fs.mutex.unlock(fs.io);
    return candidate;
}

fn replyEntry(req: c.fuse_req_t, node: *Inode, st: c.struct_stat) void {
    const entry: c.struct_fuse_entry_param = .{
        .ino = nodeNumber(node),
        .generation = 1,
        .attr = st,
        .attr_timeout = 0.05,
        .entry_timeout = 0.05,
    };
    _ = c.fuse_reply_entry(req, &entry);
}

fn initCb(userdata: ?*anyopaque, conn_opt: ?*c.struct_fuse_conn_info) callconv(.c) void {
    const fs: *Fs = @ptrCast(@alignCast(userdata orelse return));
    const conn = conn_opt orelse return;
    if (fs.passthrough_requested and c.fuse_set_feature_flag(conn, c.FUSE_CAP_PASSTHROUGH)) {
        fuse.connSetBackingDepth(conn, c.FUSE_BACKING_STACKED_OVER);
        fs.passthrough_capable = true;
    } else if (fs.passthrough_requested) {
        log.warn(@src(), "FUSE passthrough unavailable; using userspace I/O", .{});
    }
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_ASYNC_READ);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_AUTO_INVAL_DATA);
    _ = c.fuse_set_feature_flag(conn, c.FUSE_CAP_POSIX_ACL);
}

fn lookupCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name_z: [*c]const u8) callconv(.c) void {
    if (name_z == null) return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    if (parent == &fs.root and std.mem.eql(u8, name, internal_trash))
        return replyErr(req, c.ENOENT);
    var path_buffer: [max_path]u8 = undefined;
    const path = childPath(parent.path, name, &path_buffer) orelse
        return replyErr(req, c.ENOENT);
    _ = visible(fs, path, .metadata) orelse return replyErr(req, c.ENOENT);

    const fd = c.openat(parent.fd, name_z, c.O_PATH | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    var st: c.struct_stat = undefined;
    const rc = c.fstat(fd, &st);
    if (rc != 0) {
        const err = @intFromEnum(std.c.errno(rc));
        _ = c.close(fd);
        return replyErr(req, err);
    }
    const node = publish(fs, path, fd, &st) orelse {
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    replyEntry(req, node, st);
}

fn forgetCb(req: c.fuse_req_t, ino: c.fuse_ino_t, count: u64) callconv(.c) void {
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    fs.mutex.lockUncancelable(fs.io);
    node.lookup_count -|= count;
    const detached = detachLocked(fs, node);
    fs.mutex.unlock(fs.io);
    if (detached) destroyNode(node);
    c.fuse_reply_none(req);
}

fn getattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = fi;
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    _ = visible(fs, node.path, .metadata) orelse return replyErr(req, c.ENOENT);
    var st: c.struct_stat = undefined;
    const err = statNode(node, &st);
    if (err != 0) return replyErr(req, err);
    _ = c.fuse_reply_attr(req, &st, 0.05);
}

fn readlinkCb(req: c.fuse_req_t, ino: c.fuse_ino_t) callconv(.c) void {
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    _ = visible(fs, node.path, .read) orelse return replyErr(req, c.ENOENT);
    var buffer: [max_path]u8 = undefined;
    const len = c.readlinkat(node.fd, "", &buffer, buffer.len - 1);
    if (len < 0) return replyErr(req, @intFromEnum(std.c.errno(len)));
    buffer[@intCast(len)] = 0;
    _ = c.fuse_reply_readlink(req, &buffer);
}

fn accessCb(req: c.fuse_req_t, ino: c.fuse_ino_t, mask: c_int) callconv(.c) void {
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    const operation: Operation = if (mask & c.W_OK != 0) .write else .metadata;
    const access = visible(fs, node.path, operation) orelse return replyErr(req, c.ENOENT);
    if (mask & c.W_OK != 0 and access != .rw) return replyErr(req, c.EACCES);
    replyErr(req, 0);
}

fn wantsWrite(flags: c_int) bool {
    const mode = flags & c.O_ACCMODE;
    return mode == c.O_WRONLY or mode == c.O_RDWR or flags & c.O_TRUNC != 0;
}

fn openHandle(req: c.fuse_req_t, node: *Inode, fi: *c.struct_fuse_file_info, access: Access) void {
    const fs = fsFrom(req);
    const flags = (fuse.FileInfo.flags(fi) & ~@as(c_int, c.O_CREAT | c.O_EXCL | c.O_NOCTTY)) |
        c.O_CLOEXEC;
    const fd = openNode(node, flags);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    const handle = allocator.create(Handle) catch {
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    handle.* = .{ .fd = fd, .inode = node, .access = access };
    if (fs.passthrough_capable) {
        handle.backing_id = c.fuse_passthrough_open(req, fd);
        if (handle.backing_id > 0)
            fuse.FileInfo.setBackingId(fi, handle.backing_id);
    }
    fs.mutex.lockUncancelable(fs.io);
    node.open_count += 1;
    fs.mutex.unlock(fs.io);
    fuse.FileInfo.setFh(fi, @intFromPtr(handle));
    fuse.FileInfo.setKeepCache(fi, 0);
    _ = c.fuse_reply_open(req, fi);
}

fn openCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi_opt: ?*c.struct_fuse_file_info) callconv(.c) void {
    const fi = fi_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    const writing = wantsWrite(fuse.FileInfo.flags(fi));
    const access = visible(fs, node.path, if (writing) .write else .read) orelse
        return replyErr(req, c.ENOENT);
    if (writing and access != .rw) return replyErr(req, c.EACCES);
    openHandle(req, node, fi, access);
}

fn handleFrom(fi: ?*c.struct_fuse_file_info) ?*Handle {
    const info = fi orelse return null;
    return @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
}

fn readCb(req: c.fuse_req_t, ino: c.fuse_ino_t, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    const buffer = allocator.alloc(u8, size) catch return replyErr(req, c.ENOMEM);
    defer allocator.free(buffer);
    const got = c.pread(handle.fd, buffer.ptr, buffer.len, off);
    if (got < 0) return replyErr(req, @intFromEnum(std.c.errno(got)));
    _ = c.fuse_reply_buf(req, buffer.ptr, @intCast(got));
}

fn writeCb(req: c.fuse_req_t, ino: c.fuse_ino_t, data: [*c]const u8, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    if (handle.access != .rw) return replyErr(req, c.EACCES);
    const written = c.pwrite(handle.fd, data, size, off);
    if (written < 0) return replyErr(req, @intFromEnum(std.c.errno(written)));
    _ = c.fuse_reply_write(req, @intCast(written));
}

fn flushCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    const copy = c.dup(handle.fd);
    if (copy < 0) return replyErr(req, @intFromEnum(std.c.errno(copy)));
    const rc = c.close(copy);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn fsyncCb(req: c.fuse_req_t, ino: c.fuse_ino_t, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    const rc = if (datasync != 0) c.fdatasync(handle.fd) else c.fsync(handle.fd);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn releaseCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, 0);
    const fs = fsFrom(req);
    const node = handle.inode;
    if (handle.backing_id > 0 and c.fuse_passthrough_close(req, handle.backing_id) < 0)
        log.warn(@src(), "failed to close passthrough backing id {}", .{handle.backing_id});
    _ = c.close(handle.fd);
    allocator.destroy(handle);
    fs.mutex.lockUncancelable(fs.io);
    std.debug.assert(node.open_count != 0);
    node.open_count -= 1;
    const detached = detachLocked(fs, node);
    fs.mutex.unlock(fs.io);
    if (detached) destroyNode(node);
    replyErr(req, 0);
}

fn opendirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi_opt: ?*c.struct_fuse_file_info) callconv(.c) void {
    const fi = fi_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    const access = visible(fs, node.path, .read) orelse return replyErr(req, c.ENOENT);
    const fd = openNode(node, c.O_RDONLY | c.O_DIRECTORY);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    const stream = c.fdopendir(fd) orelse {
        const err = @intFromEnum(std.c.errno(-1));
        _ = c.close(fd);
        return replyErr(req, err);
    };
    const handle = allocator.create(DirHandle) catch {
        _ = c.closedir(stream);
        return replyErr(req, c.ENOMEM);
    };
    handle.* = .{ .stream = stream, .inode = node, .access = access };
    fs.mutex.lockUncancelable(fs.io);
    node.open_count += 1;
    fs.mutex.unlock(fs.io);
    fuse.FileInfo.setFh(fi, @intFromPtr(handle));
    fuse.FileInfo.setCacheReaddir(fi, 0);
    _ = c.fuse_reply_open(req, fi);
}

fn dirHandleFrom(fi: ?*c.struct_fuse_file_info) ?*DirHandle {
    const info = fi orelse return null;
    return @ptrFromInt(@as(usize, @intCast(fuse.FileInfo.fh(info))));
}

fn direntType(kind: u8) c.mode_t {
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

fn readdirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, requested: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const fs = fsFrom(req);
    const handle = dirHandleFrom(fi) orelse return replyErr(req, c.EBADF);
    const capacity = @min(requested, dir_buffer_size);
    var reply: [dir_buffer_size]u8 = undefined;
    var used: usize = 0;
    handle.mutex.lockUncancelable(fs.io);
    defer handle.mutex.unlock(fs.io);
    c.seekdir(handle.stream, @intCast(off));
    while (used < capacity) {
        const entry = c.readdir(handle.stream) orelse break;
        const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
        const special = std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..");
        if (handle.inode == &fs.root and std.mem.eql(u8, name, internal_trash))
            continue;
        if (!special) {
            var path_buffer: [max_path]u8 = undefined;
            const path = childPath(handle.inode.path, name, &path_buffer) orelse continue;
            _ = visible(fs, path, .metadata) orelse continue;
        }
        var st = std.mem.zeroes(c.struct_stat);
        st.st_ino = entry.*.d_ino;
        st.st_mode = direntType(entry.*.d_type);
        const needed = c.fuse_add_direntry(
            req,
            reply[used..].ptr,
            capacity - used,
            @ptrCast(&entry.*.d_name),
            &st,
            @intCast(c.telldir(handle.stream)),
        );
        if (needed > capacity - used) break;
        used += needed;
    }
    _ = c.fuse_reply_buf(req, &reply, used);
}

fn releasedirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = dirHandleFrom(fi) orelse return replyErr(req, 0);
    const fs = fsFrom(req);
    const node = handle.inode;
    _ = c.closedir(handle.stream);
    allocator.destroy(handle);
    fs.mutex.lockUncancelable(fs.io);
    std.debug.assert(node.open_count != 0);
    node.open_count -= 1;
    const detached = detachLocked(fs, node);
    fs.mutex.unlock(fs.io);
    if (detached) destroyNode(node);
    replyErr(req, 0);
}

fn fsyncdirCb(req: c.fuse_req_t, ino: c.fuse_ino_t, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = dirHandleFrom(fi) orelse return replyErr(req, c.EBADF);
    const fd = c.dirfd(handle.stream);
    const rc = if (datasync != 0) c.fdatasync(fd) else c.fsync(fd);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn statfsCb(req: c.fuse_req_t, ino: c.fuse_ino_t) callconv(.c) void {
    _ = ino;
    var st: c.struct_statvfs = undefined;
    const rc = c.fstatvfs(fsFrom(req).root_fd, &st);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    _ = c.fuse_reply_statfs(req, &st);
}

fn mutationPath(fs: *Fs, parent: *Inode, name_z: [*c]const u8, buffer: *[max_path]u8) ?[:0]u8 {
    if (name_z == null or !writable(fs, parent.path, .write)) return null;
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    if (parent == &fs.root and std.mem.eql(u8, name, internal_trash))
        return null;
    return childPath(parent.path, name, buffer);
}

const Creation = struct {
    path: [:0]u8,
    replaces_hidden: bool,
};

fn creationPath(
    fs: *Fs,
    parent: *Inode,
    name_z: [*c]const u8,
    buffer: *[max_path]u8,
) ?Creation {
    const path = mutationPath(fs, parent, name_z, buffer) orelse return null;
    const access = resolve(fs, path, .create) orelse return null;
    if (access == .r) return null;
    return .{ .path = path, .replaces_hidden = access == .whiteout };
}

fn removeHiddenFile(parent: *Inode, name: [*c]const u8) c_int {
    const rc = c.unlinkat(parent.fd, name, 0);
    if (rc == 0 or std.c.errno(rc) == .NOENT) return 0;
    return @intFromEnum(std.c.errno(rc));
}

fn moveHiddenDirectory(fs: *Fs, parent: *Inode, name: [*c]const u8) c_int {
    const mkdir_rc = c.mkdirat(fs.root_fd, internal_trash, @as(c.mode_t, 0o700));
    if (mkdir_rc != 0 and std.c.errno(mkdir_rc) != .EXIST)
        return @intFromEnum(std.c.errno(mkdir_rc));
    var trash_name_buffer: [128]u8 = undefined;
    const trash_name = std.fmt.bufPrintZ(
        &trash_name_buffer,
        internal_trash ++ "/{d}-{d}",
        .{ c.getpid(), trash_counter.fetchAdd(1, .monotonic) },
    ) catch return c.ENAMETOOLONG;
    const rc = std.os.linux.renameat2(
        parent.fd,
        name,
        fs.root_fd,
        trash_name.ptr,
        .{},
    );
    const err = std.os.linux.errno(rc);
    return if (err == .SUCCESS) 0 else @intFromEnum(err);
}

fn makeVisible(path: []const u8) void {
    policy.set(path, .rw) catch |err|
        log.err(@src(), "created object but failed to publish rw policy; path={s}, error={t}", .{ path, err });
}

fn mknodCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name: [*c]const u8, mode: c.mode_t, rdev: c.dev_t) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    var path_buffer: [max_path]u8 = undefined;
    const creation = creationPath(fs, parent, name, &path_buffer) orelse return replyErr(req, c.EACCES);
    if (creation.replaces_hidden) {
        const err = removeHiddenFile(parent, name);
        if (err != 0) return replyErr(req, err);
    }
    const rc = c.mknodat(parent.fd, name, mode, rdev);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    makeVisible(creation.path);
    lookupCb(req, parent_ino, name);
}

fn mkdirCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name: [*c]const u8, mode: c.mode_t) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    var path_buffer: [max_path]u8 = undefined;
    const creation = creationPath(fs, parent, name, &path_buffer) orelse return replyErr(req, c.EACCES);
    if (creation.replaces_hidden) {
        const rc = c.unlinkat(parent.fd, name, c.AT_REMOVEDIR);
        if (rc != 0 and std.c.errno(rc) != .NOENT) {
            const move_err = moveHiddenDirectory(fs, parent, name);
            if (move_err != 0) return replyErr(req, move_err);
        }
    }
    const rc = c.mkdirat(parent.fd, name, mode);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    makeVisible(creation.path);
    lookupCb(req, parent_ino, name);
}

fn symlinkCb(req: c.fuse_req_t, link: [*c]const u8, parent_ino: c.fuse_ino_t, name: [*c]const u8) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    var path_buffer: [max_path]u8 = undefined;
    const creation = creationPath(fs, parent, name, &path_buffer) orelse return replyErr(req, c.EACCES);
    if (creation.replaces_hidden) {
        const err = removeHiddenFile(parent, name);
        if (err != 0) return replyErr(req, err);
    }
    const rc = c.symlinkat(link, parent.fd, name);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    makeVisible(creation.path);
    lookupCb(req, parent_ino, name);
}

fn unlinkLike(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name: [*c]const u8, flags: c_int) void {
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    var path_buffer: [max_path]u8 = undefined;
    const path = mutationPath(fs, parent, name, &path_buffer) orelse return replyErr(req, c.EACCES);
    _ = visible(fs, path, .write) orelse return replyErr(req, c.ENOENT);
    const rc = c.unlinkat(parent.fd, name, flags);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    policy.set(path, .whiteout) catch |err|
        log.err(@src(), "unlink succeeded but whiteout policy update failed; path={s}, error={t}", .{ path, err });
    replyErr(req, 0);
}

fn unlinkCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8) callconv(.c) void {
    unlinkLike(req, parent, name, 0);
}

fn rmdirCb(req: c.fuse_req_t, parent: c.fuse_ino_t, name: [*c]const u8) callconv(.c) void {
    unlinkLike(req, parent, name, c.AT_REMOVEDIR);
}

fn renameCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name: [*c]const u8, newparent_ino: c.fuse_ino_t, newname: [*c]const u8, flags: c_uint) callconv(.c) void {
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    const newparent = nodeFrom(fs, newparent_ino);
    if (!writable(fs, parent.path, .write) or !writable(fs, newparent.path, .write))
        return replyErr(req, c.EACCES);
    const rc = std.os.linux.renameat2(
        parent.fd,
        name,
        newparent.fd,
        newname,
        @bitCast(flags),
    );
    const rename_errno = std.os.linux.errno(rc);
    if (rename_errno != .SUCCESS)
        return replyErr(req, @intFromEnum(rename_errno));
    var old_buffer: [max_path]u8 = undefined;
    var new_buffer: [max_path]u8 = undefined;
    if (childPath(parent.path, std.mem.span(@as([*:0]const u8, @ptrCast(name))), &old_buffer)) |old_path|
        policy.set(old_path, .whiteout) catch |err|
            log.err(@src(), "rename succeeded but old-path policy update failed; path={s}, error={t}", .{ old_path, err });
    if (childPath(newparent.path, std.mem.span(@as([*:0]const u8, @ptrCast(newname))), &new_buffer)) |new_path|
        makeVisible(new_path);
    replyErr(req, 0);
}

fn linkCb(req: c.fuse_req_t, ino: c.fuse_ino_t, newparent_ino: c.fuse_ino_t, newname: [*c]const u8) callconv(.c) void {
    const fs = fsFrom(req);
    const source = nodeFrom(fs, ino);
    const parent = nodeFrom(fs, newparent_ino);
    _ = visible(fs, source.path, .read) orelse return replyErr(req, c.ENOENT);
    var path_buffer: [max_path]u8 = undefined;
    const creation = creationPath(fs, parent, newname, &path_buffer) orelse return replyErr(req, c.EACCES);
    if (creation.replaces_hidden) {
        const err = removeHiddenFile(parent, newname);
        if (err != 0) return replyErr(req, err);
    }
    const rc = c.linkat(source.fd, "", parent.fd, newname, c.AT_EMPTY_PATH);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    makeVisible(creation.path);
    lookupCb(req, newparent_ino, newname);
}

fn createCb(req: c.fuse_req_t, parent_ino: c.fuse_ino_t, name: [*c]const u8, mode: c.mode_t, fi_opt: ?*c.struct_fuse_file_info) callconv(.c) void {
    const fi = fi_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const parent = nodeFrom(fs, parent_ino);
    var path_buffer: [max_path]u8 = undefined;
    const creation = creationPath(fs, parent, name, &path_buffer) orelse return replyErr(req, c.EACCES);
    if (creation.replaces_hidden) {
        const err = removeHiddenFile(parent, name);
        if (err != 0) return replyErr(req, err);
    }
    const flags = fuse.FileInfo.flags(fi) | c.O_CREAT | c.O_CLOEXEC;
    const fd = c.openat(parent.fd, name, flags, mode);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    makeVisible(creation.path);
    const path_fd = c.openat(parent.fd, name, c.O_PATH | c.O_NOFOLLOW | c.O_CLOEXEC);
    if (path_fd < 0) {
        _ = c.close(fd);
        return replyErr(req, @intFromEnum(std.c.errno(path_fd)));
    }
    var st: c.struct_stat = undefined;
    if (c.fstat(path_fd, &st) != 0) {
        _ = c.close(path_fd);
        _ = c.close(fd);
        return replyErr(req, c.EIO);
    }
    const node = publish(fs, creation.path, path_fd, &st) orelse {
        _ = c.close(path_fd);
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    const handle = allocator.create(Handle) catch {
        _ = c.close(fd);
        return replyErr(req, c.ENOMEM);
    };
    handle.* = .{ .fd = fd, .inode = node, .access = .rw };
    fs.mutex.lockUncancelable(fs.io);
    node.open_count += 1;
    fs.mutex.unlock(fs.io);
    fuse.FileInfo.setFh(fi, @intFromPtr(handle));
    const entry: c.struct_fuse_entry_param = .{
        .ino = nodeNumber(node),
        .generation = 1,
        .attr = st,
        .attr_timeout = 0.05,
        .entry_timeout = 0.05,
    };
    _ = c.fuse_reply_create(req, &entry, fi);
}

fn setattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, attr_opt: ?*c.struct_stat, to_set: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    const attr = attr_opt orelse return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    if (!writable(fs, node.path, .write)) return replyErr(req, c.EACCES);
    const handle = handleFrom(fi);
    const owned_fd = if (handle) |item| item.fd else openNode(
        node,
        if (to_set & c.FUSE_SET_ATTR_SIZE != 0) c.O_RDWR else c.O_RDONLY,
    );
    if (owned_fd < 0) return replyErr(req, @intFromEnum(std.c.errno(owned_fd)));
    defer {
        if (handle == null) _ = c.close(owned_fd);
    }

    if (to_set & c.FUSE_SET_ATTR_MODE != 0 and c.fchmod(owned_fd, attr.st_mode) != 0)
        return replyErr(req, @intFromEnum(std.c.errno(-1)));
    if (to_set & (c.FUSE_SET_ATTR_UID | c.FUSE_SET_ATTR_GID) != 0) {
        const uid = if (to_set & c.FUSE_SET_ATTR_UID != 0) attr.st_uid else @as(c.uid_t, @bitCast(@as(c_int, -1)));
        const gid = if (to_set & c.FUSE_SET_ATTR_GID != 0) attr.st_gid else @as(c.gid_t, @bitCast(@as(c_int, -1)));
        if (c.fchown(owned_fd, uid, gid) != 0)
            return replyErr(req, @intFromEnum(std.c.errno(-1)));
    }
    if (to_set & c.FUSE_SET_ATTR_SIZE != 0 and c.ftruncate(owned_fd, attr.st_size) != 0)
        return replyErr(req, @intFromEnum(std.c.errno(-1)));
    if (to_set & (c.FUSE_SET_ATTR_ATIME | c.FUSE_SET_ATTR_MTIME |
        c.FUSE_SET_ATTR_ATIME_NOW | c.FUSE_SET_ATTR_MTIME_NOW) != 0)
    {
        var times = [_]c.struct_timespec{
            .{ .tv_sec = 0, .tv_nsec = c.UTIME_OMIT },
            .{ .tv_sec = 0, .tv_nsec = c.UTIME_OMIT },
        };
        if (to_set & c.FUSE_SET_ATTR_ATIME != 0) times[0] = attr.st_atim;
        if (to_set & c.FUSE_SET_ATTR_MTIME != 0) times[1] = attr.st_mtim;
        if (to_set & c.FUSE_SET_ATTR_ATIME_NOW != 0) times[0].tv_nsec = c.UTIME_NOW;
        if (to_set & c.FUSE_SET_ATTR_MTIME_NOW != 0) times[1].tv_nsec = c.UTIME_NOW;
        if (c.futimens(owned_fd, &times) != 0)
            return replyErr(req, @intFromEnum(std.c.errno(-1)));
    }
    var st: c.struct_stat = undefined;
    const rc = c.fstat(owned_fd, &st);
    if (rc != 0) return replyErr(req, @intFromEnum(std.c.errno(rc)));
    _ = c.fuse_reply_attr(req, &st, 0.05);
}

fn internalXattr(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "trusted.overlay.") or
        std.mem.startsWith(u8, name, "user.overlay.");
}

fn xattrFd(node: *Inode) c_int {
    return openNode(node, c.O_RDONLY | c.O_NONBLOCK);
}

fn setxattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, name_z: [*c]const u8, value: [*c]const u8, size: usize, flags: c_int) callconv(.c) void {
    if (name_z == null) return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    if (!writable(fs, node.path, .write)) return replyErr(req, c.EACCES);
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    if (internalXattr(name)) return replyErr(req, c.EPERM);
    const fd = xattrFd(node);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    defer _ = c.close(fd);
    const rc = c.fsetxattr(fd, name_z, value, size, flags);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn getxattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, name_z: [*c]const u8, size: usize) callconv(.c) void {
    if (name_z == null) return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    _ = visible(fs, node.path, .metadata) orelse return replyErr(req, c.ENOENT);
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    if (internalXattr(name)) return replyErr(req, c.ENODATA);
    const fd = xattrFd(node);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    defer _ = c.close(fd);
    if (size == 0) {
        const length = c.fgetxattr(fd, name_z, null, 0);
        if (length < 0) return replyErr(req, @intFromEnum(std.c.errno(length)));
        _ = c.fuse_reply_xattr(req, @intCast(length));
        return;
    }
    const buffer = allocator.alloc(u8, size) catch return replyErr(req, c.ENOMEM);
    defer allocator.free(buffer);
    const length = c.fgetxattr(fd, name_z, buffer.ptr, buffer.len);
    if (length < 0) return replyErr(req, @intFromEnum(std.c.errno(length)));
    _ = c.fuse_reply_buf(req, buffer.ptr, @intCast(length));
}

fn listxattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, size: usize) callconv(.c) void {
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    _ = visible(fs, node.path, .metadata) orelse return replyErr(req, c.ENOENT);
    const fd = xattrFd(node);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    defer _ = c.close(fd);
    const needed = c.flistxattr(fd, null, 0);
    if (needed < 0) return replyErr(req, @intFromEnum(std.c.errno(needed)));
    if (needed == 0 or size == 0) {
        _ = c.fuse_reply_xattr(req, @intCast(needed));
        return;
    }
    const raw = allocator.alloc(u8, @intCast(needed)) catch return replyErr(req, c.ENOMEM);
    defer allocator.free(raw);
    const got = c.flistxattr(fd, raw.ptr, raw.len);
    if (got < 0) return replyErr(req, @intFromEnum(std.c.errno(got)));
    var filtered: std.ArrayList(u8) = .empty;
    defer filtered.deinit(allocator);
    var start: usize = 0;
    while (start < @as(usize, @intCast(got))) {
        const end = std.mem.indexOfScalarPos(u8, raw, start, 0) orelse break;
        if (!internalXattr(raw[start..end])) {
            filtered.appendSlice(allocator, raw[start .. end + 1]) catch
                return replyErr(req, c.ENOMEM);
        }
        start = end + 1;
    }
    if (filtered.items.len > size) return replyErr(req, c.ERANGE);
    _ = c.fuse_reply_buf(req, filtered.items.ptr, filtered.items.len);
}

fn removexattrCb(req: c.fuse_req_t, ino: c.fuse_ino_t, name_z: [*c]const u8) callconv(.c) void {
    if (name_z == null) return replyErr(req, c.EINVAL);
    const fs = fsFrom(req);
    const node = nodeFrom(fs, ino);
    if (!writable(fs, node.path, .write)) return replyErr(req, c.EACCES);
    const name = std.mem.span(@as([*:0]const u8, @ptrCast(name_z)));
    if (internalXattr(name)) return replyErr(req, c.EPERM);
    const fd = xattrFd(node);
    if (fd < 0) return replyErr(req, @intFromEnum(std.c.errno(fd)));
    defer _ = c.close(fd);
    const rc = c.fremovexattr(fd, name_z);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn fallocateCb(req: c.fuse_req_t, ino: c.fuse_ino_t, mode: c_int, offset: c.off_t, length: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    if (handle.access != .rw) return replyErr(req, c.EACCES);
    const rc = c.fallocate(handle.fd, mode, offset, length);
    replyErr(req, if (rc == 0) 0 else @intFromEnum(std.c.errno(rc)));
}

fn lseekCb(req: c.fuse_req_t, ino: c.fuse_ino_t, off: c.off_t, whence: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) void {
    _ = ino;
    const handle = handleFrom(fi) orelse return replyErr(req, c.EBADF);
    const result = c.lseek(handle.fd, off, whence);
    if (result < 0) return replyErr(req, @intFromEnum(std.c.errno(result)));
    _ = c.fuse_reply_lseek(req, result);
}

fn copyFileRangeCb(
    req: c.fuse_req_t,
    ino_in: c.fuse_ino_t,
    off_in: c.off_t,
    fi_in: ?*c.struct_fuse_file_info,
    ino_out: c.fuse_ino_t,
    off_out: c.off_t,
    fi_out: ?*c.struct_fuse_file_info,
    length: usize,
    flags: c_int,
) callconv(.c) void {
    _ = ino_in;
    _ = ino_out;
    const source = handleFrom(fi_in) orelse return replyErr(req, c.EBADF);
    const destination = handleFrom(fi_out) orelse return replyErr(req, c.EBADF);
    if (destination.access != .rw) return replyErr(req, c.EACCES);
    var source_offset = off_in;
    var destination_offset = off_out;
    const copied = c.copy_file_range(
        source.fd,
        &source_offset,
        destination.fd,
        &destination_offset,
        length,
        @intCast(flags),
    );
    if (copied < 0) return replyErr(req, @intFromEnum(std.c.errno(copied)));
    _ = c.fuse_reply_write(req, @intCast(copied));
}

fn ioctlCb(
    req: c.fuse_req_t,
    ino: c.fuse_ino_t,
    command: c_uint,
    argument: ?*anyopaque,
    fi: ?*c.struct_fuse_file_info,
    flags: c_uint,
    input: ?*const anyopaque,
    input_size: usize,
    output_size: usize,
) callconv(.c) void {
    _ = ino;
    _ = command;
    _ = argument;
    _ = fi;
    _ = flags;
    _ = input;
    _ = input_size;
    _ = output_size;
    replyErr(req, c.EOPNOTSUPP);
}

pub const ops = std.mem.zeroInit(c.struct_fuse_lowlevel_ops, .{
    .init = initCb,
    .lookup = lookupCb,
    .forget = forgetCb,
    .getattr = getattrCb,
    .setattr = setattrCb,
    .readlink = readlinkCb,
    .access = accessCb,
    .open = openCb,
    .create = createCb,
    .read = readCb,
    .write = writeCb,
    .flush = flushCb,
    .fsync = fsyncCb,
    .release = releaseCb,
    .opendir = opendirCb,
    .readdir = readdirCb,
    .releasedir = releasedirCb,
    .fsyncdir = fsyncdirCb,
    .statfs = statfsCb,
    .mknod = mknodCb,
    .mkdir = mkdirCb,
    .symlink = symlinkCb,
    .unlink = unlinkCb,
    .rmdir = rmdirCb,
    .rename = renameCb,
    .link = linkCb,
    .setxattr = setxattrCb,
    .getxattr = getxattrCb,
    .listxattr = listxattrCb,
    .removexattr = removexattrCb,
    .fallocate = fallocateCb,
    .copy_file_range = copyFileRangeCb,
    .lseek = lseekCb,
    .ioctl = ioctlCb,
});

test "path joins are canonical" {
    var buffer: [max_path]u8 = undefined;
    try std.testing.expectEqualStrings("/etc", childPath("/", "etc", &buffer).?);
    try std.testing.expectEqualStrings("/usr/bin", childPath("/usr", "bin", &buffer).?);
    try std.testing.expect(childPath("/", "../x", &buffer) == null);
    try std.testing.expect(childPath("/", "a/b", &buffer) == null);
}

test "write intent includes read-only truncate" {
    try std.testing.expect(!wantsWrite(c.O_RDONLY));
    try std.testing.expect(wantsWrite(c.O_RDONLY | c.O_TRUNC));
    try std.testing.expect(wantsWrite(c.O_WRONLY));
    try std.testing.expect(wantsWrite(c.O_RDWR));
}

test "ask result cannot overwrite a concurrent explicit update" {
    const policy_fd = try std.posix.memfd_create("ask-policy", 0);
    try policy.init(std.testing.io, policy_fd);
    defer policy.deinit();
    try policy.set("/file", .ask);
    const root_fd = try std.posix.memfd_create("ask-root", 0);
    const Callback = struct {
        fn ask(_: ?*anyopaque, _: std.Io, _: AskRequest) !Access {
            try policy.set("/file", .whiteout);
            return .rw;
        }
    };
    var fs = try Fs.init(std.testing.io, root_fd, false, null, Callback.ask);
    defer fs.deinit();
    try std.testing.expectEqual(Access.whiteout, resolve(&fs, "/file", .read).?);
    try std.testing.expectEqual(Access.whiteout, (try policy.get("/file")).?);
}
