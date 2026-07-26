//! Locked wrapper around the trie data structure.
//! Holds the RwLock and the Io for external synchronisation.
const std = @import("std");
const Trie = @import("trie.zig");
const log = @import("log.zig");

pub const Mode = Trie.Mode;

/// The unlocked trie instance.
trie: Trie,
/// Serialises access to the trie for concurrent I/O.
lock: std.Io.RwLock = .init,
/// The I/O backend used by the lock primitives.
io: std.Io,

/// Open or create a trie backed by `fd`.
pub fn init(io: std.Io, fd: std.c.fd_t) !@This() {
    return .{
        .trie = try Trie.init(fd),
        .io = io,
    };
}

/// Release all pool resources.
pub fn deinit(me: *@This()) void {
    me.trie.deinit();
}

/// Insert or replace `path` with `data`. Takes the write lock, then syncs.
pub fn add(me: *@This(), path: []const u8, data: Mode) !void {
    {
        me.lock.lockUncancelable(me.io);
        defer me.lock.unlock(me.io);
        me.trie.add(path, data) catch |e| {
            log.err(@src(), "error while adding/setting the tire node data: error={}, path={s}, data={}", .{e, path, data});
            return e;
        };
    }
    me.syncAndLog();
}

/// Remove `path` and return its previous value. Takes the write lock, then syncs.
pub fn del(me: *@This(), path: []const u8) !Mode {
    const old = old: {
        me.lock.lockUncancelable(me.io);
        defer me.lock.unlock(me.io);
        break :old me.trie.del(path) catch |e| {
            log.err(@src(), "error while removing the tire node data: error={}, path={s}", .{e, path});
            return e;
        };
    };
    me.syncAndLog();
    return old;
}

/// Return the nearest slash-delimited ancestor rule for `path`. Read-only, shared lock.
pub fn get(me: *@This(), path: []const u8) !?Mode {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return me.trie.get(path);
}

/// Discard all entries and reset the trie to empty. Takes the write lock.
pub fn reset(me: *@This()) void {
    me.lock.lockUncancelable(me.io);
    defer me.lock.unlock(me.io);
    me.trie.reset();
}

/// Flush pending writes to backing storage (read-locked, called after write ops).
fn syncAndLog(me: *@This()) void {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    me.trie.sync() catch |err|
        log.err(@src(), "failed to persist committed trie update: {t}", .{err});
}

const testing = std.testing;

test "concurrent readers and writers preserve trie invariants" {
    var root = try init(std.Io.default, try std.posix.memfd_create("permbox-root-test", 0));
    defer root.deinit();

    var failed: std.atomic.Value(bool) = .init(false);
    const Self = @This();

    const Worker = struct {
        fn run(root_ptr: *Self, first_byte: u8, fail_flag: *std.atomic.Value(bool)) void {
            var path = [2]u8{ first_byte, 0 };
            for (0..250) |i| {
                path[1] = @truncate(i);
                root_ptr.add(&path, Mode.dir) catch {
                    fail_flag.store(true, .release);
                    return;
                };
                const actual = root_ptr.get(&path) catch {
                    fail_flag.store(true, .release);
                    return;
                };
                if (actual == null) {
                    fail_flag.store(true, .release);
                    return;
                }
                _ = root_ptr.del(&path) catch {
                    fail_flag.store(true, .release);
                    return;
                };
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &root, @as(u8, @intCast(i)), &failed });
    }
    for (threads) |thread| thread.join();

    try testing.expect(!failed.load(.acquire));
}
