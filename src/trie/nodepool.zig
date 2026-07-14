const std = @import("std");
const root = @import("root.zig");
const linux = std.os.linux;
const fd_t = linux.fd_t;

/// The mem for the blox
block_mem: []u8,
/// Mem for strs
radix_mem: []u8,
/// fd for block_mem
block_fd: fd_t,
/// fd for radix_mem
radix_fd: fd_t,

/// These must reside on the same fs; or atleast reside on fs's with same block sizes
pub fn init(block_fd: fd_t, radix_fd: fd_t) @This() {
}

fn getSize(fd: fd_t) !@Tuple(.{u64, u32}) {
    var result: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{.SIZE = true}, &result);
    if (rc != 0) return error.StatxFailed;
    return .{result.size, result.blksize};
}

fn resize(self: *@This(), comptime field: []const u8, new_len: u63) !void {
    const fd = @field(self, field ++ "_fd");
    if (linux.ftruncate(fd, new_len) != 0) return error.FileResizeFailed;
    const mem: *[]u8 = &@field(self, field ++ "_mem");
    if (linux.mremap(mem.ptr, mem.len, new_len, .{.MAYMOVE = true}, null) != 0) error.RemapFailed;
}

pub fn acquire(self: @This()) root.Node {
}

pub fn release(self: @This(), node: root.Node) void {
}
