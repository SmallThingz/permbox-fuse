const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const linux = std.os.linux;
const fd_t = linux.fd_t;

const check_oob = true;

const page_size_min = std.heap.page_size_min;

pub var global: @This() = undefined;

/// fd for block_mem
fd: fd_t,
/// The mem for the blox
mem: []align(page_size_min) u8,
/// The block size of the fs that this file is on
blksize: u32,

pub const InitError = StatxError || TruncateError || OOB || ValidateError;
/// These must reside on the same fs; or atleast reside on fs's with same block sizes
pub fn init(fd: fd_t) !@This() {
    const _len, const blksize = try getSize(fd);
    const initialized = _len >= 1 << 16;
    const len = @min(1 << 16, _len);

    if (!initialized) {
        if (linux.ftruncate(fd, len) != 0) return TruncateError.ResizeFailed;
    }

    const self: @This() = .{
        .fd = fd,
        .mem = mapFd(fd, len),
        .blksize = blksize,
    };

    if (!initialized) {
        const blk = self.block();
        blk.* = .{ .free_range = .{ 2, @divExact(self.mem.len, 1 << 10) }, .free_idx = 0 };
        (try self.nodeAt(1)).* = .{};
    } else {
        try self.validate();
    }

    return self;
}

const StatxError = error{StatxFailed};
fn getSize(fd: fd_t) !@Tuple(.{ u64, u32 }) {
    var result: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &result);
    if (rc != 0) return StatxError.StatxFailed;
    return .{ result.size, result.blksize };
}

const MMapError = std.posix.MMapError;
fn mapFd(fd: fd_t, len: u64) MMapError![]align(page_size_min) u8 {
    return try std.posix.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .NORESERVE = true, .HUGETLB = true }, fd, 0);
}

pub const OOB = if (check_oob) error{
    /// The file was invalid and would have done an out of bounds access
    OutOfBounds,
} else error{};
pub fn nodeAt(self: *@This(), idx: u24) OOB!*root.Node {
    const off = @as(usize, idx) << 10;
    if (check_oob) {
        if (off > self.mem.len - 1024) return OOB.OutOfBounds;
    }
    return @ptrCast(self.mem[off..][0 .. 1 << 10].ptr);
}

/// Validation error
const ValidateError = error{
    /// The file magic does not match to what was expected
    MagicMismatch,
    /// The file's version is too new. The software is out of date
    UnsupportedVersion,
    /// The endian-ness of the file mismatches the expected. Use switchEndian to change the endian-ness
    EndianMismatch,
};
fn validate(self: *@This()) ValidateError!void {
    const VE = ValidateError;
    const blk = self.block();
    if (blk.magic != MAGIC) return VE.MagicMismatch;

    if (blk.version > VERSION) {
        // FUTURE; also will need to handle endian-ness
    } else if (blk.version < VERSION) {
        return VE.UnsupportedVersion;
    }

    if (blk.endian != Endian.default) {
        return VE.EndianMismatch;
    }

    const max_idx = @divExact(self.mem.len, 1 << 10);
    if (blk.free_range.from > max_idx or blk.free_range.end != max_idx) error.InvalidBoundsInFileFreeRange;
    if (blk.free_idx >= blk.free_range.from) return error.InvalidBoundsInFileFreeList;
}

fn block(self: *@This()) Block {
    return .from(self.mem);
}

pub const SwitchEndianError = StatxError || std.posix.MMapError;

/// Changes the endian-ness and writes the result to the dest_fd
/// Does not sync the dest file; that would be the caller's responsibility
pub fn switchEndian(self: *@This(), dest_fd: fd_t) !void {
    const _len, const blksize = try getSize(dest_fd);
    if (_len != self.mem.len) {
        if (linux.ftruncate(self.fd, self.mem.len) != 0) return error.FileResizeFailed;
    }

    const dest: @This() = .{
        .fd = dest_fd,
        .mem = try mapFd(dest_fd, self.mem.len),
        .blksize = blksize,
    };

    defer std.posix.munmap(dest.mem);

    {
        var blk: Block = self.block().*;
        blk.endian = switch (blk.endian) {
            .big => .little,
            .little => .big,
        };
        std.mem.byteSwapAllFields(Block, &blk);
        dest.block().* = blk;
    }

    const is_native = self.block().isEndianNative();
    const till = if (is_native) self.block().free_from else @byteSwap(self.block().free_from);
    for (0..till) |i| {
        const node = self.nodeAt(i) catch unreachable;
        const dnode = dest.nodeAt(i) catch unreachable;

        if ((if (is_native) node.indexAt(0xff).get() else @byteSwap(node.indexAt(0xff).get())) == i) {
            dnode.indexAt(0xff).set(@byteSwap(node.indexAt(0xff).get()));
            dnode.indexAt(0xfe).set(@byteSwap(node.indexAt(0xfe).get()));
            continue;
        }

        @memcpy(@as([]align(1024) u8, dnode)[0 .. node.radix_len + 2], @as([]align(1024) u8, node)[0 .. node.radix_len + 2]);
        for (dnode.bitset, node.bitset) |*d, s| d.* = @byteSwap(s);
        for (0..node.idx_arr.len / 3) |j| {
            const a = j * 3;
            const b = a + 1;
            const c = b + 1;
            dnode.idx_arr[a] = node.idx_arr[c];
            dnode.idx_arr[b] = node.idx_arr[b];
            dnode.idx_arr[c] = node.idx_arr[a];
        }
    }
}

pub const AcquireError = OOB || ResizeError;

/// Acquire a node from the pool
pub fn acquire(self: @This()) AcquireError!u24 {
    const blk = self.block();
    if (blk.free_idx) {
        const node = try self.nodeAt(blk.free_idx);
        blk.free_idx = node.indexAt(0xfe).get();
        return node;
    }

    if (blk.free_from >= self.mem.len >> 10) {
        @branchHint(.unlikely);
        blk.free_from = self.mem.len;
        try self.resize(self.mem.len + (1 << 16));
    }

    std.debug.assert(blk.free_from < self.mem.len >> 10);
    defer blk.free_from += 1;
    return blk.free_from;
}

const TruncateError = error{ResizeFailed};
const ResizeError = TruncateError || std.posix.MRemapError;
fn resize(self: *@This(), new_len: u63) !void {
    if (linux.ftruncate(self.fd, new_len) != 0) return ResizeError.ResizeFailed;
    try std.posix.mremap(self.mem.ptr, self.mem.len, new_len, .{ .MAYMOVE = true }, null);
}

/// Release a node to the pool
pub fn release(self: @This(), idx: u24) void {
    const blk = self.block();
    if (idx == blk.free_from - 1) {
        @branchHint(.cold);
        blk.free_from -= 1;
    } else {
        const node = self.nodeAt(idx) catch unreachable;
        node.indexAt(0xff).set(idx);
        node.indexAt(0xfe).set(blk.free_idx);
        blk.free_idx = idx;
    }
}

pub fn indexOf(self: *@This(), node: *root.Node) OOB!u24 {
    const int = @intFromPtr(node);
    std.debug.assert(int & 0b11_1111_1111 == 0);
    const mem = @intFromPtr(self.mem.ptr);
    if (int < mem or int + 1024 > mem + self.mem.len) return OOB.OutOfBounds;
    return int - mem;
}

const Endian = enum(u8) {
    big = 'B',
    little = 'L',

    pub const default = @field(@This(), @tagName(builtin.cpu.arch.endian()));
};

const MAGIC = "PERMBOX" ++ "RDXTRIE";

const VERSION = 0;

const Block = packed struct {
    const Range = packed struct(u64) { start: u32, end: u32 };
    magic: [14]u8 = MAGIC,
    /// The endian-ness of the current file
    endian: Endian = .default,
    /// The version of the current file
    version: u8 = VERSION,
    /// All the blocks after this index are free
    free_from: u32,
    /// This block is free
    free_idx: u32,

    pub fn from(mem: []align(page_size_min) u8) *@This() {
        return @ptrCast(mem.ptr);
    }

    pub fn isEndianNative(self: *@This()) bool {
        return self.endian == Endian.default;
    }
};
