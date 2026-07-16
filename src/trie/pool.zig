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
        blk.* = .{ .free_range = .{ 2, @divExact(self.mem.len, 1 << 10) }, .free_from = 2, .free_idx = 0, .root = 1 };
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
    return @as(*root.Node, @ptrCast(@alignCast(self.mem[off..][0 .. 1 << 10].ptr)));
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
    if (blk.free_idx >= blk.free_from) return error.InvalidBoundsInFileFreeList;
    if (blk.root >= blk.free_from) return error.InvalidBoundsInFileFreeList;
}

pub fn block(self: *@This()) *Block {
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
pub fn acquire(self: *@This()) AcquireError!u24 {
    const blk = self.block();
    if (blk.free_idx != 0) {
        const idx = blk.free_idx;
        const node = try self.nodeAt(@intCast(idx));
        blk.free_idx = node.indexAt(0xfe).get();
        return @intCast(idx);
    }

    if (blk.free_from >= self.mem.len >> 10) {
        @branchHint(.unlikely);
        blk.free_from = @intCast(self.mem.len);
        try self.resize(@intCast(self.mem.len + (1 << 16)));
    }

    std.debug.assert(blk.free_from < self.mem.len >> 10);
    defer blk.free_from += 1;
    return @intCast(blk.free_from);
}

const TruncateError = error{ResizeFailed};
const ResizeError = TruncateError || std.posix.MRemapError;
fn resize(self: *@This(), new_len: u63) !void {
    if (linux.ftruncate(self.fd, new_len) != 0) return ResizeError.ResizeFailed;
    self.mem = try std.posix.mremap(self.mem.ptr, self.mem.len, new_len, .{ .MAYMOVE = true }, null);
}

/// Release a node to the pool
pub fn release(self: *@This(), idx: u24) void {
    const blk = self.block();
    if (idx == blk.free_from - 1) {
        @branchHint(.cold);
        blk.free_from -= 1;
    } else {
        const node = self.nodeAt(idx) catch unreachable;
        node.indexAt(0xff).set(idx);
        node.indexAt(0xfe).set(@intCast(blk.free_idx));
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

pub fn sync(self: *@This()) !void {
    return std.posix.msync(self.mem, linux.MSF.SYNC);
}

const Endian = enum(u8) {
    big = 'B',
    little = 'L',

    pub const default = @field(@This(), @tagName(builtin.cpu.arch.endian()));
};

const MAGIC = @as([14]u8, ("PERMBOX" ++ "RDXTRIE").*);

const VERSION = 0;

const Block = extern struct {
    const Range = packed struct(u64) { start: u32, end: u32 };
    magic: [14]u8 = MAGIC,
    /// The endian-ness of the current file
    endian: Endian = .default,
    /// The version of the current file
    version: u8 = VERSION,
    /// The range of free blocks
    free_range: Range = .{ .start = 2, .end = 0 },
    /// All the blocks after this index are free
    free_from: u32 = 0,
    /// This block is free
    free_idx: u32 = 0,
    /// The index of the root node
    root: u32 = 0,

    pub fn from(mem: []align(page_size_min) u8) *@This() {
        return @ptrCast(mem.ptr);
    }

    pub fn isEndianNative(self: *@This()) bool {
        return self.endian == Endian.default;
    }
};

// =========================================================================
// Pool Tests
// =========================================================================

const posix = std.posix;
const testing = std.testing;

// Helper to initialize a fresh pool for each test
fn initTestPool() !void {
    const fd = try posix.memfd_create("pool-test", 0);
    global = try init(fd);
}

test "Pool init and basic properties" {
    try initTestPool();
    const blk = global.block();

    // Initial size should be 1 << 16 (64KB) -> 64 nodes of 1KB each
    try testing.expectEqual(@as(usize, 1 << 16), global.mem.len);

    // Check block metadata
    try testing.expectEqualStrings("PERMBOXRDXTRIE", &blk.magic);
    try testing.expectEqual(@as(u8, 0), blk.version); // VERSION = 0
    try testing.expectEqual(@as(u32, 2), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);
    try testing.expectEqual(@as(u32, 1), blk.root);

    // Check free range
    try testing.expectEqual(@as(u32, 2), blk.free_range.start);
    try testing.expectEqual(@as(u32, 64), blk.free_range.end);
}

test "Pool acquire increments free_from" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire();
    try testing.expectEqual(@as(u24, 2), idx1);
    try testing.expectEqual(@as(u32, 3), blk.free_from);

    const idx2 = try global.acquire();
    try testing.expectEqual(@as(u24, 3), idx2);
    try testing.expectEqual(@as(u32, 4), blk.free_from);

    // Ensure the acquired nodes are zeroed/initialized
    const node1 = try global.nodeAt(idx1);
    try testing.expectEqual(@as(u8, 0), node1.radix_len);
}

test "Pool release to tail collapses free_from" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire(); // 2
    const idx2 = try global.acquire(); // 3
    try testing.expectEqual(@as(u32, 4), blk.free_from);

    // Releasing in reverse order should just collapse free_from
    // without populating the free_idx linked list
    global.release(idx2);
    try testing.expectEqual(@as(u32, 3), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);

    global.release(idx1);
    try testing.expectEqual(@as(u32, 2), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);
}

test "Pool release out of order uses free list (LIFO)" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire(); // 2
    const idx2 = try global.acquire(); // 3
    _ = try global.acquire(); // 4

    // Release idx2. Not a tail, so it goes to free_idx
    global.release(idx2);
    try testing.expectEqual(@as(u32, 5), blk.free_from);
    try testing.expectEqual(@as(u32, 3), blk.free_idx); // free_idx points to 3

    // Verify the free list node linkage
    const free_node = try global.nodeAt(3);
    try testing.expectEqual(@as(u24, 0), free_node.indexAt(0xfe).get()); // Next free is 0

    // Release idx1. Not a tail, goes to free_idx
    global.release(idx1);
    try testing.expectEqual(@as(u32, 5), blk.free_from);
    try testing.expectEqual(@as(u32, 2), blk.free_idx); // free_idx points to 2

    const free_node2 = try global.nodeAt(2);
    try testing.expectEqual(@as(u24, 3), free_node2.indexAt(0xfe).get()); // Next free is 3

    // Acquire should now reuse from the free list (LIFO)
    const r1 = try global.acquire();
    try testing.expectEqual(@as(u24, 2), r1);
    try testing.expectEqual(@as(u32, 3), blk.free_idx);

    const r2 = try global.acquire();
    try testing.expectEqual(@as(u24, 3), r2);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);

    // Next acquire should go back to expanding free_from
    const r3 = try global.acquire();
    try testing.expectEqual(@as(u24, 5), r3);
    try testing.expectEqual(@as(u32, 6), blk.free_from);
}

test "Pool nodeAt and indexOf inverse" {
    try initTestPool();

    const idx1 = try global.acquire();
    const idx2 = try global.acquire();

    const node1 = try global.nodeAt(idx1);
    const node2 = try global.nodeAt(idx2);

    // Write some dummy data to make sure pointers are distinct and valid
    node1.radix_len = 11;
    node2.radix_len = 22;

    const ret_idx1 = try global.indexOf(node1);
    const ret_idx2 = try global.indexOf(node2);

    try testing.expectEqual(idx1, ret_idx1);
    try testing.expectEqual(idx2, ret_idx2);

    // Verify data integrity
    try testing.expectEqual(@as(u8, 11), (try global.nodeAt(idx1)).radix_len);
    try testing.expectEqual(@as(u8, 22), (try global.nodeAt(idx2)).radix_len);
}

test "Pool nodeAt out of bounds" {
    try initTestPool();

    // Initial capacity is 64 nodes (indices 0..63)
    try testing.expectError(error.OutOfBounds, global.nodeAt(64));

    // 63 should be valid
    const node = try global.nodeAt(63);
    _ = node;
}

test "Pool indexOf out of bounds" {
    try initTestPool();

    // Create a dummy node not in the pool
    var dummy: root.Node = .{};

    // Should return OutOfBounds because the pointer is outside mem
    try testing.expectError(error.OutOfBounds, global.indexOf(&dummy));
}

test "Pool auto-resize on capacity hit" {
    try initTestPool();
    const blk = global.block();

    // Exhaust initial 64KB capacity (62 usable nodes, 0 is block, 1 is root)
    var i: u24 = 0;
    while (i < 62) : (i += 1) {
        _ = try global.acquire();
    }

    try testing.expectEqual(@as(usize, 1 << 16), global.mem.len);
    try testing.expectEqual(@as(u32, 64), blk.free_from);
    try testing.expectEqual(@as(u32, 64), blk.free_range.end);

    // This acquire should trigger a resize by 1 << 16 (64KB)
    const idx = try global.acquire();
    try testing.expectEqual(@as(u24, 64), idx);

    // Re-obtain block pointer after resize (blk from before resize is stale)
    const blk2 = global.block();

    // Check that the pool grew
    try testing.expectEqual(@as(usize, 1 << 17), global.mem.len);
    try testing.expectEqual(@as(u32, 65), blk2.free_from);
    try testing.expectEqual(@as(u32, 128), blk2.free_range.end);

    // Ensure the new node is accessible and writable
    const node = try global.nodeAt(idx);
    node.radix_len = 99;
    try testing.expectEqual(@as(u8, 99), (try global.nodeAt(idx)).radix_len);
}

test "Pool multiple resizes" {
    try initTestPool();

    // Allocate 200 nodes to force multiple resizes (64 -> 128 -> 256 nodes)
    var i: u24 = 0;
    while (i < 200) : (i += 1) {
        const idx = try global.acquire();
        const node = try global.nodeAt(idx);
        node.radix_len = @intCast(i & 0xFF);
    }

    try testing.expectEqual(@as(usize, 1 << 18), global.mem.len); // 256KB
    try testing.expectEqual(@as(u32, 202), global.block().free_from);

    // Verify data integrity for a few nodes
    try testing.expectEqual(@as(u8, 50), (try global.nodeAt(52)).radix_len); // idx = 50 + 2
    try testing.expectEqual(@as(u8, 150), (try global.nodeAt(152)).radix_len); // idx = 150 + 2
}

test "Pool re-initialization validates" {
    try initTestPool();
    const idx = try global.acquire();
    const node = try global.nodeAt(idx);
    node.radix_len = 77;

    try global.sync();

    // Capture fd, drop global, and re-init
    const fd = global.fd;
    std.posix.munmap(global.mem);
    global = undefined;

    global = try init(fd);
    const blk = global.block();
    try testing.expectEqual(@as(u32, 3), blk.free_from);
    try testing.expectEqual(@as(u8, 77), (try global.nodeAt(idx)).radix_len);
}

test "Pool switchEndian" {
    try initTestPool();
    const dest_fd = try posix.memfd_create("pool-test-dest", 0);

    // Write some data
    const idx = try global.acquire();
    const node = try global.nodeAt(idx);
    node.radix_len = 42;

    // Switch endian
    try global.switchEndian(dest_fd);

    // Map dest manually to check results
    const dest_mem = try std.posix.mmap(null, 1 << 16, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, dest_fd, 0);
    defer std.posix.munmap(dest_mem);

    const dest_blk: *Block = @ptrCast(@alignCast(dest_mem.ptr));
    try testing.expect(global.block().endian != dest_blk.endian);
    try testing.expectEqualStrings("PERMBOXRDXTRIE", &dest_blk.magic);
}

test "Pool full capacity cycle" {
    try initTestPool();

    var allocated = std.AutoHashMap(u24, void).init(testing.allocator);
    defer allocated.deinit();

    // Fill completely to capacity and a bit beyond
    var i: u24 = 0;
    while (i < 100) : (i += 1) {
        const idx = try global.acquire();
        try allocated.put(idx, {});
    }

    // Release everything randomly
    var keys = std.ArrayList(u24).init(testing.allocator);
    defer keys.deinit();
    var it = allocated.keyIterator();
    while (it.next()) |k| try keys.append(k.*);

    for (keys.items) |k| {
        global.release(k);
    }
    allocated.deinit();

    // After releasing everything, if we allocate 100 again, it should work perfectly
    i = 0;
    while (i < 100) : (i += 1) {
        _ = try global.acquire();
    }
}
