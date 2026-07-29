//! Concurrent longest-prefix policy access for the FUSE layer.
const std = @import("std");
const permtrie = @import("permtrie");

pub const Access = permtrie.Access;
pub const PathError = error{InvalidPath};

var trie: permtrie = undefined;

pub fn init(io: std.Io, fd: std.c.fd_t) !void {
    trie = try permtrie.init(io, fd);
}

pub fn deinit() void {
    trie.deinit();
}

pub fn evaluate(path: []const u8) !?Access {
    try validatePath(path);
    return trie.get(path);
}

pub fn get(path: []const u8) !?Access {
    try validatePath(path);
    return trie.getExact(path);
}

pub fn set(path: []const u8, access: Access) !void {
    try validateRule(path, access);
    try trie.add(path, access);
}

pub fn remove(path: []const u8) !Access {
    try validatePath(path);
    return trie.del(path);
}

pub fn toText(allocator: std.mem.Allocator) ![]u8 {
    return trie.toText(allocator);
}

pub fn replaceFromText(allocator: std.mem.Allocator, text: []const u8) !void {
    try trie.replaceFromText(allocator, text);
}

pub fn lockUpdates() void {
    trie.lockWrite();
}

pub fn unlockUpdates() void {
    trie.unlockWrite();
}

pub fn evaluateLocked(path: []const u8) !?Access {
    try validatePath(path);
    return trie.getLocked(path);
}

pub fn setLocked(path: []const u8, access: Access) !void {
    try validateRule(path, access);
    try trie.addLocked(path, access);
}

pub fn removeLocked(path: []const u8) !Access {
    try validatePath(path);
    return trie.delLocked(path);
}

fn validateRule(path: []const u8, access: Access) PathError!void {
    try validatePath(path);
    _ = access;
}

pub fn validatePath(path: []const u8) PathError!void {
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidPath;
    if (path.len == 1) return;
    if (path[path.len - 1] == '/') return error.InvalidPath;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return error.InvalidPath;
    }
}

test "longest prefix and exact rules use four states" {
    try init(std.testing.io, try std.posix.memfd_create("policy-test", 0));
    defer deinit();
    try set("/", .rw);
    try set("/private", .whiteout);
    try set("/private/readme", .r);
    try std.testing.expectEqual(Access.rw, (try evaluate("/other")).?);
    try std.testing.expectEqual(Access.whiteout, (try evaluate("/private/x")).?);
    try std.testing.expectEqual(Access.r, (try evaluate("/private/readme")).?);
    try std.testing.expectEqual(@as(?Access, null), try get("/private/x"));
}

test "policy paths are canonical" {
    try init(std.testing.io, try std.posix.memfd_create("policy-path-test", 0));
    defer deinit();
    for ([_][]const u8{ "", "relative", "/a/../b", "/a/./b", "/a//b", "/a/" }) |path|
        try std.testing.expectError(error.InvalidPath, evaluate(path));
}
