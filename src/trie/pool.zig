const std = @import("std");
const builtin = @import("builtin");
const trie = @import("trie.zig");
const log = @import("log.zig");

const posix = std.posix;
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

pub const InitError = StatxError || TruncateError || MMapError || OOB || ValidateError;
/// This struct now owns the fd and the fd will be released when upon deinit.
/// If this errors; the fd remains valid
pub fn init(fd: fd_t) InitError!@This() {
    const _len, const blksize = try getSize(fd);
    const initialized = _len >= 1 << 16;
    const len = if (initialized) _len else @as(u64, 1 << 16);

    if (!initialized) {
        if (linux.ftruncate(fd, @intCast(len)) != 0) return TruncateError.ResizeFailed;
    }

    var self: @This() = .{
        .fd = fd,
        .mem = try mapFd(fd, len),
        .blksize = blksize,
    };
    errdefer posix.munmap(self.mem);

    if (!initialized) {
        const blk = self.block();
        blk.* = .{ .free_from = 1, .free_idx = 0, .root = 0 };
    } else {
        try self.validate();
    }

    return self;
}

pub fn reset(self: *@This()) void {
    const blk = self.block();
    blk.root = 0;
    blk.free_from = 1;
    blk.free_idx = 0;
    self.resize(1 << 16) catch |err|
        log.err("failed to shrink reset pool: {t}", .{err});
}

pub fn deinit(self: *@This()) void {
    _ = linux.close(self.fd);
    posix.munmap(self.mem);
    self.* = undefined;
}

const StatxError = error{StatxFailed};
fn getSize(fd: fd_t) !@Tuple(&.{ u64, u32 }) {
    var result: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &result);
    if (rc != 0) return StatxError.StatxFailed;
    return .{ result.size, result.blksize };
}

const MMapError = posix.MMapError;
fn mapFd(fd: fd_t, len: u64) MMapError![]align(page_size_min) u8 {
    return try posix.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0);
}

pub const OOB = if (check_oob) error{
    /// The file was invalid and would have done an out of bounds access
    OutOfBounds,
} else error{};
pub fn nodeAt(self: *@This(), idx: u24) OOB!*trie.Node {
    const off = @as(usize, idx) << 10;
    if (check_oob) {
        if (idx == 0 or idx >= self.mem.len >> 10) return OOB.OutOfBounds;
    }
    return @ptrCast(@alignCast(self.mem[off..][0 .. 1 << 10].ptr));
}

/// Returns an allocated node that is not currently on the free list.
pub fn activeNodeAt(self: *@This(), idx: u24) OOB!*trie.Node {
    if (idx == 0 or idx >= self.block().free_from) return OOB.OutOfBounds;
    const node = try self.nodeAt(idx);
    if (node.indexAt(0xff).get() == idx) return OOB.OutOfBounds;
    return node;
}

/// Validation error
const ValidateError = error{
    /// The file is larger that 16 GiB which is not supported
    FileTooLong,
    /// The file magic does not match to what was expected
    MagicMismatch,
    /// The file's version is too new. The software is out of date
    UnsupportedVersion,
    /// The endian-ness of the file mismatches the expected. Use switchEndian to change the endian-ness
    EndianMismatch,
    /// The file's free_from field
    OOBFreeFrom,
    /// The file's free_idx field
    OOBFreeIdx,
    /// The root node lies out of bounds
    OOBRootNode,
};
fn validate(self: *@This()) ValidateError!void {
    const VE = ValidateError;
    if (self.mem.len > (1 << 34) - 1024) return VE.FileTooLong;
    const blk = self.block();
    if (!std.mem.eql(u8, &blk.magic, &MAGIC)) return VE.MagicMismatch;
    if (blk.endian != Endian.default) return VE.EndianMismatch;

    if (blk.version < VERSION) {
        // This will start erroring if the VERSION is incremented
        @compileError("TODO: implement older version handling");
    } else if (blk.version > VERSION) {
        return VE.UnsupportedVersion;
    }

    const max_idx = self.mem.len / (1 << 10);
    if (blk.free_from < 1 or blk.free_from > max_idx) return VE.OOBFreeFrom;
    if (blk.free_idx >= blk.free_from) return VE.OOBFreeIdx;
    if (blk.root >= blk.free_from) return VE.OOBRootNode;
    if (blk.root == 0) self.reset();
}

pub fn block(self: *@This()) *Block {
    return .from(self.mem);
}

pub const SwitchEndianError = TruncateError || StatxError || posix.MMapError;

/// Changes the endian-ness and writes the result to the dest_fd
/// Does not sync the dest file; that would be the caller's responsibility
pub fn switchEndian(self: *@This(), dest_fd: fd_t) SwitchEndianError!void {
    const _len, const blksize = try getSize(dest_fd);
    if (_len != self.mem.len) {
        if (linux.ftruncate(dest_fd, @intCast(self.mem.len)) != 0) return TruncateError.ResizeFailed;
    }

    var dest: @This() = .{
        .fd = dest_fd,
        .mem = try mapFd(dest_fd, self.mem.len),
        .blksize = blksize,
    };

    defer posix.munmap(dest.mem);

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
    for (1..till) |i| {
        const node = self.nodeAt(@intCast(i)) catch unreachable;
        const dnode = dest.nodeAt(@intCast(i)) catch unreachable;

        if ((if (is_native) node.indexAt(0xff).get() else @byteSwap(node.indexAt(0xff).get())) == i) {
            dnode.indexAt(0xff).set(@byteSwap(node.indexAt(0xff).get()));
            dnode.indexAt(0xfe).set(@byteSwap(node.indexAt(0xfe).get()));
            continue;
        }

        const len = @as(usize, node.radix_len) + 2;
        @memcpy(std.mem.asBytes(dnode)[0..len], std.mem.asBytes(node)[0..len]);
        for (&dnode.bitset.masks, node.bitset.masks) |*d, s| d.* = @byteSwap(s);
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

pub const AcquireError = OOB || ResizeError || error{FileTooLong};

/// Acquire a node from the pool
pub fn acquire(self: *@This()) AcquireError!u24 {
    var blk = self.block();
    if (blk.free_idx != 0) {
        const idx = blk.free_idx;
        const node = try self.nodeAt(@intCast(idx));
        blk.free_idx = node.indexAt(0xfe).get();
        node.indexAt(0xff).set(0);
        node.indexAt(0xfe).set(0);
        return @intCast(idx);
    }

    if (blk.free_from >= self.mem.len >> 10) {
        @branchHint(.unlikely);
        if (self.mem.len + (1 << 16) > (1 << 34) - 1024) {
            @branchHint(.cold);
            if (self.mem.len >= (1 << 34) - 1024) {
                @branchHint(.likely);
                return AcquireError.FileTooLong;
            } else {
                @branchHint(.cold);
                try self.resize((1 << 34) - 1024);
            }
        } else {
            try self.resize(self.mem.len + (1 << 16));
        }
        // re-obtain block pointer after resize (mem may have moved)
        blk = self.block();
    }

    std.debug.assert(blk.free_from <= self.mem.len >> 10);
    defer blk.free_from += 1;
    return @intCast(blk.free_from);
}

const TruncateError = error{ResizeFailed};
const ResizeError = TruncateError || posix.MRemapError;
fn resize(self: *@This(), new_len: usize) !void {
    if (linux.ftruncate(self.fd, @intCast(new_len)) != 0) return ResizeError.ResizeFailed;
    self.mem = try posix.mremap(self.mem.ptr, self.mem.len, new_len, .{ .MAYMOVE = true }, null);
}

/// Release a node to the pool
pub fn release(self: *@This(), idx: u24) OOB!void {
    const blk = self.block();
    if (comptime check_oob) {
        if (idx == 0 or idx >= blk.free_from) return OOB.OutOfBounds;
        const node = try self.nodeAt(idx);
        if (node.indexAt(0xff).get() == idx) return OOB.OutOfBounds;
    }

    if (idx == blk.free_from - 1) {
        @branchHint(.cold);
        blk.free_from -= 1;
    } else {
        const node = self.nodeAt(idx) catch unreachable;
        // Since a node can't point to itself; this is a loop
        node.indexAt(0xff).set(idx);
        node.indexAt(0xfe).set(@intCast(blk.free_idx));
        blk.free_idx = idx;
    }
}

pub fn indexOf(self: *@This(), node: *trie.Node) OOB!u24 {
    const int = @intFromPtr(node);
    const mem = @intFromPtr(self.mem.ptr);
    if ((int & 0b11_1111_1111) != 0) return OOB.OutOfBounds;
    // Overflow-safe bounds check
    if (int < mem) return OOB.OutOfBounds;
    const offset = int - mem;
    if (offset > self.mem.len - 1024) return OOB.OutOfBounds;
    return @intCast(offset >> 10);
}

pub fn sync(self: *@This()) !void {
    return posix.msync(self.mem, linux.MSF.SYNC);
}

const Endian = enum(u8) {
    big = 'B',
    little = 'L',

    pub const default = @field(@This(), @tagName(builtin.cpu.arch.endian()));
};

const MAGIC = @as([14]u8, ("PERMBOX" ++ "RDXTRIE").*);

const VERSION = 0;

pub const Block = extern struct {
    magic: [14]u8 = MAGIC,
    /// The endian-ness of the current file
    endian: Endian = .default,
    /// The version of the current file
    version: u8 = VERSION,
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
    try testing.expectEqual(@as(u32, 1), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);
    try testing.expectEqual(@as(u32, 0), blk.root);
}

test "Pool acquire increments free_from" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire();
    try testing.expectEqual(@as(u24, 1), idx1);
    try testing.expectEqual(@as(u32, 2), blk.free_from);

    const idx2 = try global.acquire();
    try testing.expectEqual(@as(u24, 2), idx2);
    try testing.expectEqual(@as(u32, 3), blk.free_from);

    // Ensure the acquired nodes are zeroed/initialized
    const node1 = try global.nodeAt(idx1);
    try testing.expectEqual(@as(u8, 0), node1.radix_len);
}

test "Pool release to tail collapses free_from" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire(); // 1
    const idx2 = try global.acquire(); // 2
    try testing.expectEqual(@as(u32, 3), blk.free_from);

    // Releasing in reverse order should just collapse free_from
    // without populating the free_idx linked list
    try global.release(idx2);
    try testing.expectEqual(@as(u32, 2), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);

    try global.release(idx1);
    try testing.expectEqual(@as(u32, 1), blk.free_from);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);
}

test "Pool release out of order uses free list (LIFO)" {
    try initTestPool();
    const blk = global.block();

    const idx1 = try global.acquire(); // 1
    const idx2 = try global.acquire(); // 2
    _ = try global.acquire(); // 3

    // Release idx2. Not a tail, so it goes to free_idx
    try global.release(idx2);
    try testing.expectEqual(@as(u32, 4), blk.free_from);
    try testing.expectEqual(@as(u32, 2), blk.free_idx); // free_idx points to 2

    // Verify the free list node linkage
    const free_node = try global.nodeAt(2);
    try testing.expectEqual(@as(u24, 0), free_node.indexAt(0xfe).get()); // Next free is 0

    // Release idx1. Not a tail, goes to free_idx
    try global.release(idx1);
    try testing.expectEqual(@as(u32, 4), blk.free_from);
    try testing.expectEqual(@as(u32, 1), blk.free_idx); // free_idx points to 1

    const free_node2 = try global.nodeAt(1);
    try testing.expectEqual(@as(u24, 2), free_node2.indexAt(0xfe).get()); // Next free is 2

    // Acquire should now reuse from the free list (LIFO)
    const r1 = try global.acquire();
    try testing.expectEqual(@as(u24, 1), r1);
    try testing.expectEqual(@as(u32, 2), blk.free_idx);

    const r2 = try global.acquire();
    try testing.expectEqual(@as(u24, 2), r2);
    try testing.expectEqual(@as(u32, 0), blk.free_idx);

    // Next acquire should go back to expanding free_from
    const r3 = try global.acquire();
    try testing.expectEqual(@as(u24, 4), r3);
    try testing.expectEqual(@as(u32, 5), blk.free_from);
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
    var dummy: trie.Node = .{};

    // Should return OutOfBounds because the pointer is outside mem
    try testing.expectError(error.OutOfBounds, global.indexOf(&dummy));
}

test "Pool auto-resize on capacity hit" {
    try initTestPool();
    const blk = global.block();

    // Exhaust initial 64KB capacity (63 usable nodes, 0 is block)
    var i: u24 = 0;
    while (i < 63) : (i += 1) {
        _ = try global.acquire();
    }

    try testing.expectEqual(@as(usize, 1 << 16), global.mem.len);
    try testing.expectEqual(@as(u32, 64), blk.free_from);

    // This acquire should trigger a resize by 1 << 16 (64KB)
    const idx = try global.acquire();
    try testing.expectEqual(@as(u24, 64), idx);

    // Re-obtain block pointer after resize (blk from before resize is stale)
    const blk2 = global.block();

    // Check that the pool grew
    try testing.expectEqual(@as(usize, 1 << 17), global.mem.len);
    try testing.expectEqual(@as(u32, 65), blk2.free_from);

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
    try testing.expectEqual(@as(u32, 201), global.block().free_from);

    // Verify data integrity for a few nodes
    try testing.expectEqual(@as(u8, 50), (try global.nodeAt(51)).radix_len); // idx = 50 + 1
    try testing.expectEqual(@as(u8, 150), (try global.nodeAt(151)).radix_len); // idx = 150 + 1
}

test "Pool re-initialization validates" {
    try initTestPool();
    const idx = try global.acquire();
    const node = try global.nodeAt(idx);
    node.radix_len = 77;

    // Set root to idx so validate() doesn't call reset() and wipe the pool
    global.block().root = idx;

    try global.sync();

    // Capture fd, drop global, and re-init
    const fd = global.fd;
    std.posix.munmap(global.mem);
    global = undefined;

    global = try init(fd);
    const blk = global.block();
    try testing.expectEqual(@as(u32, 2), blk.free_from);
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
    var keys = std.ArrayList(u24).empty;
    defer keys.deinit(testing.allocator);
    var it = allocated.keyIterator();
    while (it.next()) |k| try keys.append(testing.allocator, k.*);

    for (keys.items) |k| {
        try global.release(k);
    }

    // After releasing everything, if we allocate 100 again, it should work perfectly
    i = 0;
    while (i < 100) : (i += 1) {
        _ = try global.acquire();
    }
}
