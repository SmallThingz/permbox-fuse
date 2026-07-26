//! Durable sparse-overlay sessions and restart-safe application.
//!
//! A session directory contains:
//!   format       - format marker
//!   data/<id>    - sparse data extents
//!   ranges/<id>  - exact native-endian { offset, length } write records
//!   paths/<id>   - the normalized absolute backing path
//!   apply.log    - durable per-id range-journal offsets
//!
//! Applying a file is idempotent. The target is synced before its journal
//! offset is appended and synced in apply.log, so a crash can at worst replay
//! the uncheckpointed ranges.
const std = @import("std");
const log = @import("log.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("dirent.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

const format_contents = "permbox-overlay-v1\n";
const id_len = 32;
const max_path = 4096;

pub const Range = extern struct {
    offset: u64,
    length: u64,
};

comptime {
    std.debug.assert(@sizeOf(Range) == 16);
    std.debug.assert(@alignOf(Range) == @alignOf(u64));
}

pub const Error = error{
    InvalidSession,
    InvalidPath,
    HashCollision,
    IncompleteEntry,
    UnsupportedFile,
    Io,
    OutOfMemory,
};

pub const ApplyOptions = struct {
    /// Stop after this many previously-unapplied files. Null means no limit.
    max_files: ?usize = null,
    /// Remove overlay data and path records after their apply checkpoint is
    /// durable. The apply log remains the recovery authority.
    remove_applied: bool = false,
};

pub const ApplyResult = struct {
    applied: usize,
    skipped: usize,
    remaining: usize,

    pub fn complete(self: ApplyResult) bool {
        return self.remaining == 0;
    }
};

pub const Session = struct {
    io: std.Io,
    root_fd: c_int,
    data_fd: c_int,
    ranges_fd: c_int,
    paths_fd: c_int,
    mutex: std.Io.Mutex = .init,

    pub fn open(io: std.Io, path: [:0]const u8, create: bool) Error!Session {
        const root_fd = c.open(
            path.ptr,
            c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC,
        );
        if (root_fd < 0) {
            const open_errno: c_int = @intFromEnum(std.posix.errno(root_fd));
            if (!create or open_errno != c.ENOENT) {
                log.err(@src(), "open session root failed; path={s}, create={}, errno={}", .{ path, create, open_errno });
                return error.Io;
            }
            const mkdir_rc = c.mkdir(path.ptr, 0o700);
            const mkdir_errno: c_int = @intFromEnum(std.posix.errno(mkdir_rc));
            if (mkdir_rc != 0 and mkdir_errno != c.EEXIST) {
                log.err(@src(), "mkdir session root failed; path={s}, errno={}", .{ path, mkdir_errno });
                return error.Io;
            }
        }
        const opened_root = if (root_fd >= 0) root_fd else c.open(
            path.ptr,
            c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC,
        );
        if (opened_root < 0) {
            log.err(@src(), "reopen session root after mkdir failed; path={s}, errno={}", .{ path, @intFromEnum(std.posix.errno(opened_root)) });
            return error.Io;
        }
        errdefer _ = c.close(opened_root);

        try ensureFormat(opened_root, create);
        try ensureDir(opened_root, "data", create);
        try ensureDir(opened_root, "ranges", create);
        try ensureDir(opened_root, "paths", create);
        const root_sync_rc = if (create) c.fsync(opened_root) else 0;
        if (root_sync_rc != 0) {
            log.err(@src(), "fsync session root failed; path={s}, errno={}", .{ path, @intFromEnum(std.posix.errno(root_sync_rc)) });
            return error.Io;
        }

        const data_fd = c.openat(opened_root, "data", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (data_fd < 0) {
            log.err(@src(), "open data dir failed; root={s}, errno={}", .{ path, @intFromEnum(std.posix.errno(data_fd)) });
            return error.Io;
        }
        errdefer _ = c.close(data_fd);
        const paths_fd = c.openat(opened_root, "paths", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (paths_fd < 0) {
            log.err(@src(), "open paths dir failed; root={s}, errno={}", .{ path, @intFromEnum(std.posix.errno(paths_fd)) });
            return error.Io;
        }
        errdefer _ = c.close(paths_fd);
        const ranges_fd = c.openat(opened_root, "ranges", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (ranges_fd < 0) {
            log.err(@src(), "open ranges dir failed; root={s}, errno={}", .{ path, @intFromEnum(std.posix.errno(ranges_fd)) });
            return error.Io;
        }
        errdefer _ = c.close(ranges_fd);

        return .{
            .io = io,
            .root_fd = opened_root,
            .data_fd = data_fd,
            .ranges_fd = ranges_fd,
            .paths_fd = paths_fd,
        };
    }

    pub fn deinit(self: *Session) void {
        _ = c.close(self.paths_fd);
        _ = c.close(self.ranges_fd);
        _ = c.close(self.data_fd);
        _ = c.close(self.root_fd);
        self.* = undefined;
    }

    pub fn duplicateDataFd(self: *const Session) Error!c_int {
        const fd = c.fcntl(self.data_fd, c.F_DUPFD_CLOEXEC, @as(c_int, 0));
        if (fd < 0) log.err(@src(), "fcntl(DUPFD_CLOEXEC) for data_fd failed; fd={}, errno={}", .{ self.data_fd, @intFromEnum(std.posix.errno(fd)) });
        return if (fd < 0) error.Io else fd;
    }

    pub fn duplicatePathsFd(self: *const Session) Error!c_int {
        const fd = c.fcntl(self.paths_fd, c.F_DUPFD_CLOEXEC, @as(c_int, 0));
        if (fd < 0) log.err(@src(), "fcntl(DUPFD_CLOEXEC) for paths_fd failed; fd={}, errno={}", .{ self.paths_fd, @intFromEnum(std.posix.errno(fd)) });
        return if (fd < 0) error.Io else fd;
    }

    /// Records the reverse mapping before overlay data is made writable.
    pub fn register(self: *Session, path: []const u8) Error![id_len:0]u8 {
        if (!validPath(path)) {
            log.err(@src(), "register called with invalid path; path={s}", .{path});
            return error.InvalidPath;
        }
        var id = overlayId(path);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const existing = c.openat(self.paths_fd, &id, c.O_RDONLY | c.O_CLOEXEC);
        if (existing >= 0) {
            var buf: [max_path]u8 = undefined;
            const got = c.pread(existing, &buf, buf.len, 0);
            const read_errno: c_int = if (got < 0) @intFromEnum(std.posix.errno(got)) else 0;
            _ = c.close(existing);
            if (got < 0) {
                log.err(@src(), "read existing path record failed; id={s}, errno={}", .{ id, read_errno });
                return error.Io;
            }
            const existing_path = buf[0..@intCast(got)];
            if (!std.mem.eql(u8, existing_path, path)) {
                log.err(@src(), "hash collision; id={s}, existing={s}, path={s}", .{ id, existing_path, path });
                return error.HashCollision;
            }
            return id;
        }
        const existing_errno: c_int = @intFromEnum(std.posix.errno(existing));
        if (existing_errno != c.ENOENT) {
            log.err(@src(), "open existing path record failed; id={s}, errno={}", .{ id, existing_errno });
            return error.Io;
        }

        // Publish only a completely written record. A crash may leave an
        // ignored pending file, never a torn final path mapping.
        var pending_buf: [96]u8 = undefined;
        const pending = std.fmt.bufPrintZ(&pending_buf, "{s}.{d}.{x}.pending", .{
            id[0..id_len],
            c.getpid(),
            @intFromPtr(self),
        }) catch unreachable;
        const fd = c.openat(
            self.paths_fd,
            pending.ptr,
            c.O_WRONLY | c.O_CREAT | c.O_TRUNC | c.O_NOFOLLOW | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        if (fd < 0) {
            log.err(@src(), "open pending path record failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(fd)) });
            return error.Io;
        }
        const written = c.pwrite(fd, path.ptr, path.len, 0);
        if (written != @as(isize, @intCast(path.len))) {
            log.err(@src(), "write pending path record failed; id={s}, wanted={d}, wrote={d}, errno={}", .{
                id,
                path.len,
                written,
                if (written < 0) @intFromEnum(std.posix.errno(written)) else 0,
            });
            _ = c.close(fd);
            _ = c.unlinkat(self.paths_fd, pending.ptr, 0);
            return error.Io;
        }
        const data_sync_rc = c.fdatasync(fd);
        if (data_sync_rc != 0) {
            log.err(@src(), "sync pending path record failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(data_sync_rc)) });
            _ = c.close(fd);
            _ = c.unlinkat(self.paths_fd, pending.ptr, 0);
            return error.Io;
        }
        _ = c.close(fd);
        const link_rc = c.linkat(self.paths_fd, pending.ptr, self.paths_fd, &id, 0);
        if (link_rc != 0) {
            const link_errno: c_int = @intFromEnum(std.posix.errno(link_rc));
            if (link_errno != c.EEXIST) {
                log.err(@src(), "publish path record failed; id={s}, errno={}", .{ id, link_errno });
                _ = c.unlinkat(self.paths_fd, pending.ptr, 0);
                return error.Io;
            }
        }
        const unlink_rc = c.unlinkat(self.paths_fd, pending.ptr, 0);
        const unlink_errno: c_int = @intFromEnum(std.posix.errno(unlink_rc));
        if (unlink_rc != 0 and unlink_errno != c.ENOENT) {
            log.warn(@src(), "remove pending path record failed; id={s}, errno={}", .{ id, unlink_errno });
        }
        const paths_sync_rc = c.fsync(self.paths_fd);
        if (paths_sync_rc != 0) {
            log.err(@src(), "sync paths directory after publish failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(paths_sync_rc)) });
            return error.Io;
        }

        // A cross-process winner must map the hash to the same path.
        const published = c.openat(self.paths_fd, &id, c.O_RDONLY | c.O_CLOEXEC);
        if (published < 0) {
            log.err(@src(), "verify-open published path failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(published)) });
            return error.Io;
        }
        defer _ = c.close(published);
        var published_buf: [max_path]u8 = undefined;
        const published_len = c.pread(published, &published_buf, published_buf.len, 0);
        if (published_len < 0) {
            log.err(@src(), "verify-read published path failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(published_len)) });
            return error.Io;
        }
        if (!std.mem.eql(u8, published_buf[0..@intCast(published_len)], path)) {
            log.err(@src(), "verify mismatch; id={s}, published={s}, path={s}", .{ id, published_buf[0..@intCast(published_len)], path });
            return error.HashCollision;
        }
        return id;
    }

    /// Applies pending sparse extents to `backing_path`. This method may be
    /// called repeatedly, across process restarts, or with a file limit.
    pub fn apply(
        self: *Session,
        allocator: std.mem.Allocator,
        backing_path: [:0]const u8,
        options: ApplyOptions,
    ) Error!ApplyResult {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const backing_fd = c.open(backing_path.ptr, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (backing_fd < 0) {
            log.err(@src(), "open backing dir for apply failed; path={s}, errno={}", .{ backing_path, @intFromEnum(std.posix.errno(backing_fd)) });
            return error.Io;
        }
        defer _ = c.close(backing_fd);

        const log_fd = c.openat(
            self.root_fd,
            "apply.log",
            c.O_RDWR | c.O_CREAT | c.O_APPEND | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        if (log_fd < 0) {
            log.err(@src(), "open/create apply checkpoint log failed; root_fd={}, errno={}", .{ self.root_fd, @intFromEnum(std.posix.errno(log_fd)) });
            return error.Io;
        }
        defer _ = c.close(log_fd);
        const root_sync_rc = c.fsync(self.root_fd);
        if (root_sync_rc != 0) {
            log.err(@src(), "fsync root dir before apply failed; errno={}", .{@intFromEnum(std.posix.errno(root_sync_rc))});
            return error.Io;
        }

        var completed = std.StringHashMapUnmanaged(u64).empty;
        defer {
            var it = completed.keyIterator();
            while (it.next()) |key| allocator.free(key.*);
            completed.deinit(allocator);
        }
        try readCompleted(allocator, log_fd, &completed);

        // A dup shares the directory stream offset with paths_fd. Open a new
        // file description so repeated partial applications always rescan.
        const scan_fd = c.openat(
            self.root_fd,
            "paths",
            c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC,
        );
        if (scan_fd < 0) {
            log.err(@src(), "open paths dir for apply scan failed; errno={}", .{@intFromEnum(std.posix.errno(scan_fd))});
            return error.Io;
        }
        const directory = c.fdopendir(scan_fd) orelse {
            log.err(@src(), "fdopendir for apply scan failed; errno={}", .{@intFromEnum(std.posix.errno(@as(c_int, -1)))});
            _ = c.close(scan_fd);
            return error.Io;
        };
        defer _ = c.closedir(directory);

        var result: ApplyResult = .{ .applied = 0, .skipped = 0, .remaining = 0 };
        while (c.readdir(directory)) |entry| {
            const name = std.mem.span(@as([*:0]const u8, @ptrCast(&entry.*.d_name)));
            if (name.len != id_len or name[0] == '.') continue;
            const journal_end = rangeJournalEnd(self, name) catch |err| switch (err) {
                error.IncompleteEntry => {
                    result.remaining += 1;
                    continue;
                },
                else => return err,
            };
            var journal_start = completed.get(name) orelse 0;
            // remove_applied permits a later mount to recreate the same id.
            if (journal_start > journal_end) journal_start = 0;
            if (journal_start == journal_end) {
                result.skipped += 1;
                continue;
            }
            if (options.max_files) |limit| {
                if (result.applied >= limit) {
                    result.remaining += 1;
                    continue;
                }
            }

            applyOne(self, backing_fd, name, journal_start, journal_end) catch |err| switch (err) {
                error.IncompleteEntry => {
                    result.remaining += 1;
                    continue;
                },
                else => return err,
            };
            try appendCheckpoint(log_fd, name, journal_end);
            result.applied += 1;

            if (options.remove_applied) {
                // Reset before unlinking. A crash before the unlink may cause
                // one harmless re-apply; a recreated journal can never be
                // mistaken for the prior generation.
                try appendCheckpoint(log_fd, name, 0);
                const data_unlink_rc = c.unlinkat(self.data_fd, name.ptr, 0);
                const data_errno: c_int = @intFromEnum(std.posix.errno(data_unlink_rc));
                if (data_unlink_rc != 0 and data_errno != c.ENOENT) {
                    log.err(@src(), "unlink data failed; id={s}, errno={}", .{ name, data_errno });
                    return error.Io;
                }
                const ranges_unlink_rc = c.unlinkat(self.ranges_fd, name.ptr, 0);
                const ranges_errno: c_int = @intFromEnum(std.posix.errno(ranges_unlink_rc));
                if (ranges_unlink_rc != 0 and ranges_errno != c.ENOENT) {
                    log.err(@src(), "unlink ranges failed; id={s}, errno={}", .{ name, ranges_errno });
                    return error.Io;
                }
                const paths_unlink_rc = c.unlinkat(self.paths_fd, name.ptr, 0);
                const paths_errno: c_int = @intFromEnum(std.posix.errno(paths_unlink_rc));
                if (paths_unlink_rc != 0 and paths_errno != c.ENOENT) {
                    log.err(@src(), "unlink paths failed; id={s}, errno={}", .{ name, paths_errno });
                    return error.Io;
                }
            }
        }
        return result;
    }
};

pub fn overlayId(path: []const u8) [id_len:0]u8 {
    var result: [id_len:0]u8 = undefined;
    _ = std.fmt.bufPrint(result[0..id_len], "{x:0>16}{x:0>16}", .{
        std.hash.Wyhash.hash(0, path),
        std.hash.Wyhash.hash(0x9e3779b97f4a7c15, path),
    }) catch unreachable;
    result[id_len] = 0;
    return result;
}

fn appendCheckpoint(fd: c_int, id: []const u8, offset: u64) Error!void {
    var buffer: [64]u8 = undefined;
    const checkpoint = std.fmt.bufPrint(&buffer, "{s} {d}\n", .{ id, offset }) catch unreachable;
    const written = c.write(fd, checkpoint.ptr, checkpoint.len);
    if (written != @as(isize, @intCast(checkpoint.len))) {
        log.err(@src(), "write checkpoint failed; fd={}, id={s}, offset={}, wanted={d}, wrote={d}, errno={}", .{
            fd,
            id,
            offset,
            checkpoint.len,
            written,
            if (written < 0) @intFromEnum(std.posix.errno(written)) else 0,
        });
        return error.Io;
    }
    const sync_rc = c.fdatasync(fd);
    if (sync_rc != 0) {
        log.err(@src(), "sync checkpoint failed; fd={}, id={s}, offset={}, errno={}", .{ fd, id, offset, @intFromEnum(std.posix.errno(sync_rc)) });
        return error.Io;
    }
}

fn ensureFormat(root_fd: c_int, create: bool) Error!void {
    var fd = c.openat(root_fd, "format", c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) {
        const open_errno: c_int = @intFromEnum(std.posix.errno(fd));
        if (!create or open_errno != c.ENOENT) {
            log.err(@src(), "open format file failed; root_fd={}, create={}, errno={}", .{ root_fd, create, open_errno });
            return error.InvalidSession;
        }
        fd = c.openat(
            root_fd,
            "format",
            c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_CLOEXEC,
            @as(c.mode_t, 0o600),
        );
        if (fd < 0) {
            log.err(@src(), "create format file failed; root_fd={}, errno={}", .{ root_fd, @intFromEnum(std.posix.errno(fd)) });
            return error.Io;
        }
        defer _ = c.close(fd);
        const written = c.write(fd, format_contents, format_contents.len);
        if (written != format_contents.len) {
            log.err(@src(), "write format marker failed; root_fd={}, wanted={d}, wrote={d}, errno={}", .{
                root_fd,
                format_contents.len,
                written,
                if (written < 0) @intFromEnum(std.posix.errno(written)) else 0,
            });
            return error.Io;
        }
        const data_sync_rc = c.fdatasync(fd);
        if (data_sync_rc != 0) {
            log.err(@src(), "sync format marker failed; root_fd={}, errno={}", .{ root_fd, @intFromEnum(std.posix.errno(data_sync_rc)) });
            return error.Io;
        }
        const root_sync_rc = c.fsync(root_fd);
        if (root_sync_rc != 0) {
            log.err(@src(), "sync session root after format creation failed; root_fd={}, errno={}", .{ root_fd, @intFromEnum(std.posix.errno(root_sync_rc)) });
            return error.Io;
        }
        return;
    }
    defer _ = c.close(fd);
    var buf: [format_contents.len]u8 = undefined;
    const got = c.pread(fd, &buf, buf.len, 0);
    if (got != buf.len or !std.mem.eql(u8, &buf, format_contents)) {
        log.err(@src(), "format file content mismatch; root_fd={}, got={d}", .{ root_fd, got });
        return error.InvalidSession;
    }
}

fn ensureDir(root_fd: c_int, name: [*:0]const u8, create: bool) Error!void {
    if (!create) {
        const fd = c.openat(root_fd, name, c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
        if (fd < 0) {
            log.err(@src(), "open subdir failed; root_fd={}, name={s}, errno={}", .{ root_fd, name, @intFromEnum(std.posix.errno(fd)) });
            return error.InvalidSession;
        }
        _ = c.close(fd);
        return;
    }
    const rc = c.mkdirat(root_fd, name, 0o700);
    if (rc == 0) return;
    const err: c_int = @intFromEnum(std.posix.errno(rc));
    if (err == c.EEXIST) return;
    log.err(@src(), "mkdirat subdir failed; root_fd={}, name={s}, errno={}", .{ root_fd, name, err });
    return error.Io;
}

fn validPath(path: []const u8) bool {
    if (path.len < 2 or path.len >= max_path or path[0] != '/' or path[path.len - 1] == '/')
        return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
            return false;
    }
    return true;
}

fn readCompleted(
    allocator: std.mem.Allocator,
    fd: c_int,
    completed: *std.StringHashMapUnmanaged(u64),
) Error!void {
    var st: c.struct_stat = undefined;
    const stat_rc = c.fstat(fd, &st);
    if (stat_rc != 0) {
        log.err(@src(), "fstat apply.log failed; fd={}, errno={}", .{ fd, @intFromEnum(std.posix.errno(stat_rc)) });
        return error.Io;
    }
    if (st.st_size == 0) return;
    if (st.st_size < 0 or st.st_size > 64 * 1024 * 1024) {
        log.err(@src(), "apply.log size out of range; size={}", .{st.st_size});
        return error.InvalidSession;
    }
    const contents = allocator.alloc(u8, @intCast(st.st_size)) catch return error.OutOfMemory;
    defer allocator.free(contents);
    const got = c.pread(fd, contents.ptr, contents.len, 0);
    if (got != @as(isize, @intCast(contents.len))) {
        log.err(@src(), "read apply checkpoint log failed; fd={}, wanted={d}, got={d}, errno={}", .{
            fd,
            contents.len,
            got,
            if (got < 0) @intFromEnum(std.posix.errno(got)) else 0,
        });
        return error.Io;
    }
    const parsed_len = if (std.mem.lastIndexOfScalar(u8, contents, '\n')) |last_newline|
        last_newline + 1
    else
        0;
    if (parsed_len != contents.len) {
        // A checkpoint write may have been interrupted before fdatasync.
        const truncate_rc = c.ftruncate(fd, @intCast(parsed_len));
        if (truncate_rc != 0) {
            log.err(@src(), "truncate torn checkpoint failed; fd={}, valid_bytes={d}, errno={}", .{ fd, parsed_len, @intFromEnum(std.posix.errno(truncate_rc)) });
            return error.Io;
        }
        const sync_rc = c.fdatasync(fd);
        if (sync_rc != 0) {
            log.err(@src(), "sync truncated checkpoint log failed; fd={}, valid_bytes={d}, errno={}", .{ fd, parsed_len, @intFromEnum(std.posix.errno(sync_rc)) });
            return error.Io;
        }
    }
    var lines = std.mem.splitScalar(u8, contents[0..parsed_len], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line.len <= id_len or line[id_len] != ' ') {
            log.err(@src(), "malformed checkpoint line; line={s}", .{line});
            return error.InvalidSession;
        }
        const id = line[0..id_len];
        const checkpoint = std.fmt.parseInt(u64, line[id_len + 1 ..], 10) catch {
            log.err(@src(), "invalid checkpoint offset; line={s}", .{line});
            return error.InvalidSession;
        };
        if (completed.getPtr(id)) |value| {
            value.* = checkpoint;
            continue;
        }
        const owned = allocator.dupe(u8, id) catch return error.OutOfMemory;
        errdefer allocator.free(owned);
        completed.put(allocator, owned, checkpoint) catch return error.OutOfMemory;
    }
}

fn rangeJournalEnd(session: *Session, id: []const u8) Error!u64 {
    var id_z: [id_len:0]u8 = undefined;
    @memcpy(id_z[0..id_len], id);
    id_z[id_len] = 0;
    const fd = c.openat(session.ranges_fd, &id_z, c.O_RDONLY | c.O_CLOEXEC);
    const open_errno: c_int = @intFromEnum(std.posix.errno(fd));
    if (fd < 0) return if (open_errno == c.ENOENT) error.IncompleteEntry else blk: {
        log.err(@src(), "open range journal failed; id={s}, errno={}", .{ id, open_errno });
        break :blk error.Io;
    };
    defer _ = c.close(fd);
    var st: c.struct_stat = undefined;
    const stat_rc = c.fstat(fd, &st);
    if (stat_rc != 0) {
        log.err(@src(), "fstat range journal failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(stat_rc)) });
        return error.Io;
    }
    if (st.st_size < 0) {
        log.err(@src(), "range journal has negative size; id={s}, size={d}", .{ id, st.st_size });
        return error.InvalidSession;
    }
    return @divFloor(@as(u64, @intCast(st.st_size)), @sizeOf(Range)) * @sizeOf(Range);
}

fn applyOne(
    session: *Session,
    backing_fd: c_int,
    id: []const u8,
    journal_start: u64,
    journal_end: u64,
) Error!void {
    var id_z: [id_len:0]u8 = undefined;
    @memcpy(id_z[0..id_len], id);
    id_z[id_len] = 0;

    const path_fd = c.openat(session.paths_fd, &id_z, c.O_RDONLY | c.O_CLOEXEC);
    if (path_fd < 0) {
        log.err(@src(), "applyOne: open path record failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(path_fd)) });
        return error.Io;
    }
    defer _ = c.close(path_fd);
    var path_buf: [max_path]u8 = undefined;
    const path_len = c.pread(path_fd, &path_buf, path_buf.len, 0);
    if (path_len < 0) {
        log.err(@src(), "apply path: read path record failed; id={s}, errno={}", .{ id, @intFromEnum(std.posix.errno(path_len)) });
        return error.Io;
    }
    if (path_len == 0) {
        log.err(@src(), "apply path: empty path record; id={s}", .{id});
        return error.InvalidPath;
    }
    const path = path_buf[0..@intCast(path_len)];
    if (!validPath(path)) {
        log.err(@src(), "apply path: invalid path record; id={s}, path={s}", .{ id, path });
        return error.InvalidPath;
    }
    path_buf[@intCast(path_len)] = 0;

    const overlay_fd = c.openat(session.data_fd, &id_z, c.O_RDONLY | c.O_CLOEXEC);
    const overlay_errno: c_int = @intFromEnum(std.posix.errno(overlay_fd));
    if (overlay_fd < 0) return if (overlay_errno == c.ENOENT) blk: {
        log.warn(@src(), "applyOne: overlay data missing; id={s}", .{id});
        break :blk error.IncompleteEntry;
    } else blk: {
        log.err(@src(), "applyOne: open overlay data failed; id={s}, errno={}", .{ id, overlay_errno });
        break :blk error.Io;
    };
    defer _ = c.close(overlay_fd);
    const ranges_fd = c.openat(session.ranges_fd, &id_z, c.O_RDONLY | c.O_CLOEXEC);
    const ranges_errno: c_int = @intFromEnum(std.posix.errno(ranges_fd));
    if (ranges_fd < 0) return if (ranges_errno == c.ENOENT) blk: {
        log.warn(@src(), "applyOne: range journal missing; id={s}", .{id});
        break :blk error.IncompleteEntry;
    } else blk: {
        log.err(@src(), "applyOne: open range journal failed; id={s}, errno={}", .{ id, ranges_errno });
        break :blk error.Io;
    };
    defer _ = c.close(ranges_fd);
    const target_fd = openBeneath(backing_fd, path_buf[1..@intCast(path_len) :0]);
    if (target_fd < 0) return error.Io;
    defer _ = c.close(target_fd);
    var target_stat: c.struct_stat = undefined;
    const target_stat_rc = c.fstat(target_fd, &target_stat);
    if (target_stat_rc != 0) {
        log.err(@src(), "applyOne: fstat target failed; id={s}, path={s}, errno={}", .{ id, path, @intFromEnum(std.posix.errno(target_stat_rc)) });
        return error.Io;
    }
    if (target_stat.st_mode & c.S_IFMT != c.S_IFREG) {
        log.err(@src(), "applyOne: target not a regular file; id={s}, path={s}, mode={o}", .{ id, path, target_stat.st_mode });
        return error.UnsupportedFile;
    }

    var journal_offset = journal_start;
    var records: [256]Range = undefined;
    var buffer: [64 * 1024]u8 = undefined;
    while (journal_offset < journal_end) {
        const record_bytes: usize = @intCast(@min(
            @as(u64, @sizeOf(@TypeOf(records))),
            journal_end - journal_offset,
        ));
        const got_records = c.pread(ranges_fd, &records, record_bytes, @intCast(journal_offset));
        if (got_records <= 0 or @rem(got_records, @sizeOf(Range)) != 0) {
            log.err(@src(), "apply path: invalid range-journal read; id={s}, offset={d}, got={d}, errno={}", .{
                id,
                journal_offset,
                got_records,
                if (got_records < 0) @intFromEnum(std.posix.errno(got_records)) else 0,
            });
            return error.Io;
        }
        for (records[0..@intCast(@divExact(got_records, @sizeOf(Range)))]) |record| {
            if (record.length == 0 or record.offset > std.math.maxInt(c.off_t) or
                record.length > std.math.maxInt(c.off_t) - record.offset)
            {
                log.err(@src(), "applyOne: invalid range record; id={s}, offset={d}, length={d}", .{ id, record.offset, record.length });
                return error.InvalidSession;
            }
            var cursor: u64 = record.offset;
            const end = record.offset + record.length;
            while (cursor < end) {
                const amount: usize = @intCast(@min(
                    @as(u64, buffer.len),
                    end - cursor,
                ));
                const got = c.pread(overlay_fd, &buffer, amount, @intCast(cursor));
                if (got <= 0) {
                    log.err(@src(), "apply path: overlay data read failed; id={s}, cursor={d}, wanted={d}, got={d}, errno={}", .{
                        id,
                        cursor,
                        amount,
                        got,
                        if (got < 0) @intFromEnum(std.posix.errno(got)) else 0,
                    });
                    return error.Io;
                }
                const written = c.pwrite(target_fd, &buffer, @intCast(got), @intCast(cursor));
                if (written != got) {
                    log.err(@src(), "apply path: target write failed; id={s}, cursor={d}, wanted={d}, wrote={d}, errno={}", .{
                        id,
                        cursor,
                        got,
                        written,
                        if (written < 0) @intFromEnum(std.posix.errno(written)) else 0,
                    });
                    return error.Io;
                }
                cursor += @intCast(got);
            }
        }
        journal_offset += @intCast(got_records);
    }
    const sync_rc = c.fsync(target_fd);
    if (sync_rc != 0) {
        log.err(@src(), "applyOne: fsync target failed; id={s}, path={s}, errno={}", .{ id, path, @intFromEnum(std.posix.errno(sync_rc)) });
        return error.Io;
    }
}

/// Opens each directory component with O_NOFOLLOW so a session path can never
/// escape the configured backing root through an intermediate symlink.
fn openBeneath(root_fd: c_int, relative: [:0]u8) c_int {
    var directory_fd = c.fcntl(root_fd, c.F_DUPFD_CLOEXEC, @as(c_int, 0));
    if (directory_fd < 0) {
        log.err(@src(), "openBeneath: DUPFD root_fd failed; root_fd={}, errno={}", .{ root_fd, @intFromEnum(std.posix.errno(directory_fd)) });
        return -1;
    }
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, relative, start, '/')) |slash| {
        relative[slash] = 0;
        const next = c.openat(
            directory_fd,
            @as([*:0]const u8, @ptrCast(relative.ptr + start)),
            c.O_PATH | c.O_DIRECTORY | c.O_NOFOLLOW | c.O_CLOEXEC,
        );
        const open_errno: c_int = if (next < 0) @intFromEnum(std.posix.errno(next)) else 0;
        relative[slash] = '/';
        _ = c.close(directory_fd);
        if (next < 0) {
            log.err(@src(), "open backing directory component failed; component={s}, offset={d}, errno={}", .{
                relative[start..slash],
                start,
                open_errno,
            });
            return -1;
        }
        directory_fd = next;
        start = slash + 1;
    }
    const result = c.openat(
        directory_fd,
        @as([*:0]const u8, @ptrCast(relative.ptr + start)),
        c.O_WRONLY | c.O_NONBLOCK | c.O_NOFOLLOW | c.O_CLOEXEC,
    );
    if (result < 0) {
        log.err(@src(), "open backing target failed; target={s}, errno={}", .{ relative[start..], @intFromEnum(std.posix.errno(result)) });
    }
    _ = c.close(directory_fd);
    return result;
}

test "overlay ids are stable and path-sensitive" {
    const a = overlayId("/a");
    const again = overlayId("/a");
    const b = overlayId("/b");
    try std.testing.expectEqualStrings(&a, &again);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "path validation rejects traversal and malformed paths" {
    try std.testing.expect(validPath("/a/b"));
    try std.testing.expect(!validPath(""));
    try std.testing.expect(!validPath("/"));
    try std.testing.expect(!validPath("relative"));
    try std.testing.expect(!validPath("/a/../b"));
    try std.testing.expect(!validPath("/a//b"));
    try std.testing.expect(!validPath("/a/"));
    try std.testing.expect(!validPath("/a\x00b"));
    var maximum: [max_path]u8 = undefined;
    @memset(&maximum, 'a');
    maximum[0] = '/';
    try std.testing.expect(!validPath(&maximum));
}

test "libc return values are decoded with posix errno" {
    const rc = c.close(-1);
    try std.testing.expectEqual(@as(c_int, c.EBADF), @intFromEnum(std.posix.errno(rc)));
}

test "torn apply checkpoint tail is discarded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fd = c.openat(
        tmp.dir.handle,
        "apply.log",
        c.O_RDWR | c.O_CREAT | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    try std.testing.expect(fd >= 0);
    defer _ = c.close(fd);

    const id = "0123456789abcdef0123456789abcdef";
    const contents = id ++ " 16\n" ++ id ++ " 3";
    const written = c.write(fd, contents.ptr, contents.len);
    try std.testing.expectEqual(@as(isize, @intCast(contents.len)), written);

    var completed = std.StringHashMapUnmanaged(u64).empty;
    defer {
        var it = completed.keyIterator();
        while (it.next()) |key| std.testing.allocator.free(key.*);
        completed.deinit(std.testing.allocator);
    }
    try readCompleted(std.testing.allocator, fd, &completed);
    try std.testing.expectEqual(@as(?u64, 16), completed.get(id));

    var st: c.struct_stat = undefined;
    const stat_rc = c.fstat(fd, &st);
    try std.testing.expectEqual(@as(c_int, 0), stat_rc);
    try std.testing.expectEqual(@as(c.off_t, id.len + " 16\n".len), st.st_size);
}

test "session resumes and bounded apply is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_fd = tmp.dir.handle;
    try std.testing.expectEqual(@as(c_int, 0), c.mkdirat(tmp_fd, "backing", 0o700));
    const backing_fd = c.openat(tmp_fd, "backing", c.O_RDONLY | c.O_DIRECTORY | c.O_CLOEXEC);
    try std.testing.expect(backing_fd >= 0);
    defer _ = c.close(backing_fd);
    const target_fd = c.openat(
        backing_fd,
        "file",
        c.O_RDWR | c.O_CREAT | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    try std.testing.expect(target_fd >= 0);
    defer _ = c.close(target_fd);
    try std.testing.expectEqual(@as(isize, 6), c.write(target_fd, "abcdef", 6));

    var session_path_buf: [128]u8 = undefined;
    const session_path = try std.fmt.bufPrintZ(
        &session_path_buf,
        "/proc/self/fd/{d}/session",
        .{tmp_fd},
    );
    var backing_path_buf: [128]u8 = undefined;
    const backing_path = try std.fmt.bufPrintZ(
        &backing_path_buf,
        "/proc/self/fd/{d}/backing",
        .{tmp_fd},
    );

    var session = try Session.open(std.testing.io, session_path, true);
    const id = try session.register("/file");
    const data_fd = c.openat(
        session.data_fd,
        &id,
        c.O_RDWR | c.O_CREAT | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    try std.testing.expect(data_fd >= 0);
    try std.testing.expectEqual(@as(isize, 3), c.pwrite(data_fd, "XYZ", 3, 2));
    try std.testing.expectEqual(@as(c_int, 0), c.fsync(data_fd));
    _ = c.close(data_fd);
    const ranges_fd = c.openat(
        session.ranges_fd,
        &id,
        c.O_RDWR | c.O_CREAT | c.O_APPEND | c.O_CLOEXEC,
        @as(c.mode_t, 0o600),
    );
    try std.testing.expect(ranges_fd >= 0);
    const record = Range{ .offset = 2, .length = 3 };
    try std.testing.expectEqual(
        @as(isize, @sizeOf(Range)),
        c.write(ranges_fd, &record, @sizeOf(Range)),
    );
    try std.testing.expectEqual(@as(c_int, 0), c.fsync(ranges_fd));
    _ = c.close(ranges_fd);

    const partial = try session.apply(std.testing.allocator, backing_path, .{ .max_files = 0 });
    try std.testing.expectEqual(@as(usize, 0), partial.applied);
    try std.testing.expectEqual(@as(usize, 1), partial.remaining);
    session.deinit();

    session = try Session.open(std.testing.io, session_path, false);
    defer session.deinit();
    const resumed = try session.apply(std.testing.allocator, backing_path, .{ .max_files = 1 });
    try std.testing.expectEqual(@as(usize, 1), resumed.applied);
    try std.testing.expect(resumed.complete());

    var contents: [6]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 6), c.pread(target_fd, &contents, contents.len, 0));
    try std.testing.expectEqualStrings("abXYZf", &contents);

    const again = try session.apply(std.testing.allocator, backing_path, .{});
    try std.testing.expectEqual(@as(usize, 0), again.applied);
    try std.testing.expectEqual(@as(usize, 1), again.skipped);
    try std.testing.expect(again.complete());

    const resumed_data = c.openat(session.data_fd, &id, c.O_RDWR | c.O_CLOEXEC);
    const resumed_ranges = c.openat(
        session.ranges_fd,
        &id,
        c.O_RDWR | c.O_APPEND | c.O_CLOEXEC,
    );
    try std.testing.expect(resumed_data >= 0 and resumed_ranges >= 0);
    try std.testing.expectEqual(@as(isize, 1), c.pwrite(resumed_data, "Q", 1, 0));
    const later_record = Range{ .offset = 0, .length = 1 };
    try std.testing.expectEqual(
        @as(isize, @sizeOf(Range)),
        c.write(resumed_ranges, &later_record, @sizeOf(Range)),
    );
    _ = c.close(resumed_ranges);
    _ = c.close(resumed_data);

    const later = try session.apply(std.testing.allocator, backing_path, .{});
    try std.testing.expectEqual(@as(usize, 1), later.applied);
    try std.testing.expectEqual(@as(isize, 6), c.pread(target_fd, &contents, contents.len, 0));
    try std.testing.expectEqualStrings("QbXYZf", &contents);
}
