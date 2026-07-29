//! Locked wrapper around the trie data structure.
//! Holds the RwLock and the Io for external synchronisation.
const std = @import("std");
const Trie = @import("trie.zig");
const serialization = @import("serialization.zig");
const log = @import("log.zig");

pub const Access = enum(u2) {
    whiteout,
    r,
    rw,
    ask,
};
pub const TextError = serialization.Error;

pub fn parseAccessText(flags: []const u8) TextError!Access {
    return decode(serialization.parseMode(flags) catch |err| return err);
}

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
pub fn add(me: *@This(), path: []const u8, data: Access) !void {
    me.lockWrite();
    defer me.unlockWrite();
    try me.addLocked(path, data);
}

/// Remove `path` and return its previous value. Takes the write lock, then syncs.
pub fn del(me: *@This(), path: []const u8) !Access {
    me.lockWrite();
    defer me.unlockWrite();
    return me.delLocked(path);
}

/// Return the nearest slash-delimited ancestor rule for `path`. Read-only, shared lock.
pub fn get(me: *@This(), path: []const u8) !?Access {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return if (try me.trie.get(path)) |mode| decode(mode) else null;
}

/// Return only the rule stored at `path`, without ancestor inheritance.
pub fn getExact(me: *@This(), path: []const u8) !?Access {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    return if (try me.trie.getExact(path)) |mode| decode(mode) else null;
}

/// Serialize every explicit binary-trie rule to canonical permbox `fs` text.
pub fn toText(me: *@This(), allocator: std.mem.Allocator) ![]u8 {
    me.lock.lockSharedUncancelable(me.io);
    defer me.lock.unlockShared(me.io);
    const rules = try me.trie.collectRules(allocator);
    defer {
        for (rules) |rule| allocator.free(rule.path);
        allocator.free(rules);
    }
    return serialization.format(allocator, rules);
}

/// Replace the binary trie with rules parsed from permbox `fs` text.
/// Parsing completes before the write lock is taken. Once mutation starts,
/// readers remain blocked until all rules have been installed and synced.
pub fn replaceFromText(me: *@This(), allocator: std.mem.Allocator, text: []const u8) !void {
    const rules = try serialization.parse(allocator, text);
    defer serialization.freeRules(allocator, rules);

    me.lockWrite();
    defer me.unlockWrite();
    me.trie.reset();
    for (rules) |rule| me.trie.add(rule.path, rule.mode) catch |err| {
        log.err(@src(), "failed to import parsed trie rule; error={t}, path={s}", .{ err, rule.path });
        return err;
    };
    me.syncLocked();
}

/// Begin an atomic multi-operation update. The Locked methods below may only
/// be called while this write lock is held.
pub fn lockWrite(me: *@This()) void {
    me.lock.lockUncancelable(me.io);
}

pub fn unlockWrite(me: *@This()) void {
    me.lock.unlock(me.io);
}

pub fn getLocked(me: *@This(), path: []const u8) !?Access {
    return if (try me.trie.get(path)) |mode| decode(mode) else null;
}

pub fn getExactLocked(me: *@This(), path: []const u8) !?Access {
    return if (try me.trie.getExact(path)) |mode| decode(mode) else null;
}

pub fn addLocked(me: *@This(), path: []const u8, data: Access) !void {
    me.trie.add(path, encode(data)) catch |err| {
        log.err(@src(), "failed to set trie rule; error={t}, path={s}, mode={}", .{ err, path, data });
        return err;
    };
    me.syncLocked();
}

pub fn delLocked(me: *@This(), path: []const u8) !Access {
    const old = me.trie.del(path) catch |err| {
        log.err(@src(), "failed to remove trie rule; error={t}, path={s}", .{ err, path });
        return err;
    };
    me.syncLocked();
    return decode(old);
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

fn encode(access: Access) Trie.Mode {
    return switch (access) {
        .whiteout => .whiteout,
        .r => .r,
        .rw => .rw,
        .ask => .ask,
    };
}

fn decode(mode: Trie.Mode) Access {
    return switch (mode) {
        .whiteout => .whiteout,
        .r => .r,
        .rw => .rw,
        .ask => .ask,
        .midway => unreachable,
    };
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
                root_ptr.add(&path, .rw) catch {
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

test "text serialization round trips all policy states" {
    var root = try init(std.testing.io, try std.posix.memfd_create("permbox-text-roundtrip", 0));
    defer root.deinit();

    const modes = [_]Access{ .whiteout, .r, .ask };
    try root.add("/a", modes[0]);
    try root.add("/a/quoted\"\\name", modes[1]);
    try root.add("/z", modes[2]);

    const text = try root.toText(std.testing.allocator);
    defer std.testing.allocator.free(text);
    root.reset();
    try root.replaceFromText(std.testing.allocator, text);

    try std.testing.expectEqual(modes[0], (try root.getExact("/a")).?);
    try std.testing.expectEqual(modes[1], (try root.getExact("/a/quoted\"\\name")).?);
    try std.testing.expectEqual(modes[2], (try root.getExact("/z")).?);
}

test "text import accepts nested fs syntax" {
    var root = try init(std.testing.io, try std.posix.memfd_create("permbox-text-nested", 0));
    defer root.deinit();
    try root.replaceFromText(std.testing.allocator,
        \\fs {
        \\  "/":rw {
        \\    "home/a":r
        \\    ".ssh":whiteout
        \\  }
        \\}
    );
    try std.testing.expectEqual(Access.r, (try root.getExact("/home/a")).?);
    try std.testing.expectEqual(Access.whiteout, (try root.getExact("/.ssh")).?);
}

test "invalid text does not alter the binary trie" {
    var root = try init(std.testing.io, try std.posix.memfd_create("permbox-text-invalid", 0));
    defer root.deinit();
    try root.add("/kept", .rw);
    try std.testing.expectError(error.InvalidMode, root.replaceFromText(
        std.testing.allocator,
        "\"/bad\":invalid",
    ));
    try std.testing.expect((try root.getExact("/kept")) != null);
    try std.testing.expectError(error.InvalidPath, root.replaceFromText(
        std.testing.allocator,
        "\"/allowed/../denied\":rw",
    ));
    try std.testing.expect((try root.getExact("/kept")) != null);
}
