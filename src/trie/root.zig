//! Locked wrapper around the trie data structure.
//! Holds the RwLock and the Io for external synchronisation.
const std = @import("std");
const Trie = @import("trie.zig");
const log = @import("log.zig");

pub const Mode = Trie.Mode;

trie: Trie,
lock: std.Io.RwLock = .init,
io: std.Io,

pub fn init(io: std.Io, fd: std.c.fd_t) !@This() {
    return .{
        .trie = try Trie.init(fd),
        .io = io,
    };
}

pub fn deinit(me: *@This()) void {
    me.trie.deinit();
}

pub fn add(me: *@This(), path: []const u8, data: Mode) !void {
    {
        me.lock.lockUncancelable(me.io);
        defer me.lock.unlock(me.io);
        try me.trie.add(path, data);
    }
    me.syncAndLog();
}

pub fn del(me: *@This(), path: []const u8) !Mode {
    const old = old: {
        me.lock.lockUncancelable(me.io);
        defer me.lock.unlock(me.io);
        break :old try me.trie.del(path);
    };
    me.syncAndLog();
    return old;
}

pub fn get(me: *@This(), path: []const u8) !?Mode {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return me.trie.get(path);
}

pub fn reset(me: *@This()) void {
    me.lock.lockUncancelable(me.io);
    defer me.lock.unlock(me.io);
    me.trie.reset();
}

fn syncAndLog(me: *@This()) void {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    me.trie.sync() catch |err|
        log.err("failed to persist committed trie update: {t}", .{err});
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
