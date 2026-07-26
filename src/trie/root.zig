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
    me.lockWrite();
    defer me.unlockWrite();
    try me.addLocked(path, data);
}

/// Remove `path` and return its previous value. Takes the write lock, then syncs.
pub fn del(me: *@This(), path: []const u8) !Mode {
    me.lockWrite();
    defer me.unlockWrite();
    return me.delLocked(path);
}

/// Return the nearest slash-delimited ancestor rule for `path`. Read-only, shared lock.
pub fn get(me: *@This(), path: []const u8) !?Mode {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return me.trie.get(path);
}

/// Return only the rule stored at `path`, without ancestor inheritance.
pub fn getExact(me: *@This(), path: []const u8) !?Mode {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return me.trie.getExact(path);
}

/// Begin an atomic multi-operation update. The Locked methods below may only
/// be called while this write lock is held.
pub fn lockWrite(me: *@This()) void {
    me.lock.lockUncancelable(me.io);
}

pub fn unlockWrite(me: *@This()) void {
    me.lock.unlock(me.io);
}

pub fn getLocked(me: *@This(), path: []const u8) !?Mode {
    return me.trie.get(path);
}

pub fn getExactLocked(me: *@This(), path: []const u8) !?Mode {
    return me.trie.getExact(path);
}

pub fn addLocked(me: *@This(), path: []const u8, data: Mode) !void {
    me.trie.add(path, data) catch |err| {
        log.err(@src(), "failed to set trie rule; error={t}, path={s}, mode={}", .{ err, path, data });
        return err;
    };
    me.syncLocked();
}

pub fn delLocked(me: *@This(), path: []const u8) !Mode {
    const old = me.trie.del(path) catch |err| {
        log.err(@src(), "failed to remove trie rule; error={t}, path={s}", .{ err, path });
        return err;
    };
    me.syncLocked();
    return old;
}

/// Discard all entries and reset the trie to empty. Takes the write lock.
pub fn reset(me: *@This()) void {
    me.lock.lockUncancelable(me.io);
    defer me.lock.unlock(me.io);
    me.trie.reset();
}

fn syncLocked(me: *@This()) void {
    me.trie.sync() catch |err|
        log.err(@src(), "failed to persist committed trie update: {t}", .{err});
}

const testing = std.testing;

test "concurrent readers and writers preserve trie invariants" {
    var root = try init(std.testing.io, try std.posix.memfd_create("permbox-root-test", 0));
    defer root.deinit();

    var failed: std.atomic.Value(bool) = .init(false);
    const Self = @This();

    const Worker = struct {
        fn run(root_ptr: *Self, first_byte: u8, fail_flag: *std.atomic.Value(bool)) void {
            var path = [3]u8{ '/', first_byte, 0 };
            for (0..250) |i| {
                path[2] = @truncate(i);
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
