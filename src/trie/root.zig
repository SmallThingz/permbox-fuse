//! This has the implementation of the trie that tracks the permissions
const std = @import("std");
const builtin = @import("builtin");
const mem = @import("mem.zig");
const Pool = @import("pool.zig");

const native_endian = builtin.cpu.arch.endian();
const max_depth = 1 << 12;
const children_count = 1 << 8;
const RadixInt = u8;

pub fn add(_path: []const u8, data: Mode) !void {
    std.debug.assert(_path.len != 0);
    const b = Pool.global.block();
    var path = _path;
    var index_at_buf: [3]u8 = undefined;
    std.mem.writeInt(u24, &index_at_buf, @intCast(b.root), native_endian);
    var index_at: Node.IndexAt = .{ .at = 0, .arr = @ptrCast(&index_at_buf) };
    defer b.root = std.mem.readInt(u24, &index_at_buf, native_endian);
    var node = index_at.getNode() catch unreachable;

    blk: switch (node.next(path)) {
        .this => |idx| { // the entry already exists; only need to set data
            if (node.bitset.isSet(idx)) {
                const next = try node.indexAt(idx).getNode();
                next.data = data;
            } else {
                node.indexAt(idx).set(@as(u24, @bitCast(data)));
            }
        },
        .next => |idx| { // Go to next node
            path = path[node.radix_len + 1 ..];
            std.debug.assert(path.len != 0);
            index_at = node.indexAt(idx);
            node = try index_at.getNode();
            continue :blk node.next(path);
        },
        .diff => |idx| {
            const ogpath = path;
            path = path[idx + 1 ..];

            const left_idx: u24 = init: {
                const new_idx = try acquire();
                const new = fromIdx(new_idx) catch unreachable;
                new.radix_len = node.radix_len - idx - 1;
                new.data = node.data; // Inherit data
                @memcpy(new.radix_str[0..new.radix_len], node.radix_str[idx + 1 ..]);
                const boff = @offsetOf(Node, "bitset");
                @memcpy(std.mem.asBytes(new)[boff..], std.mem.asBytes(node)[boff..]);
                break :init new_idx;
            };
            errdefer releaseOne(left_idx);

            const need_right = path.len != 0;
            const right_idx: u24 = init: {
                if (!need_right) break :init 0;
                const new_idx = try acquire();
                const new = fromIdx(new_idx) catch unreachable;
                var current = new;
                while (true) {
                    current.radix_len = @min(path.len - 1, current.radix_str.len);
                    current.data = .midway;
                    @memcpy(current.radix_str[0..current.radix_len], path[0..current.radix_len]);

                    const next_idx = path[current.radix_len];
                    path = path[current.radix_len + 1 ..];
                    if (path.len == 0) {
                        current.indexAt(next_idx).set(@as(u24, @bitCast(data)));
                        break :init new_idx;
                    }

                    const new_next = try acquire();
                    current.bitset.set(next_idx);
                    current.indexAt(next_idx).set(new_next);
                    current = fromIdx(new_next) catch unreachable;
                }
            };
            errdefer {
                if (need_right) releaseLine(right_idx, true);
            }

            const top_idx: u24 = init: {
                const new_idx = try acquire();
                const new = fromIdx(new_idx) catch unreachable;
                new.radix_len = idx;
                new.data = .midway; // Top is just a prefix
                @memcpy(new.radix_str[0..idx], node.radix_str[0..idx]);
                new.bitset.set(node.radix_str[idx]);
                new.indexAt(node.radix_str[idx]).set(left_idx);

                if (need_right) {
                    new.bitset.set(ogpath[idx]);
                    new.indexAt(ogpath[idx]).set(right_idx);
                } else {
                    new.indexAt(ogpath[idx]).set(@as(u24, @bitCast(data)));
                }

                break :init new_idx;
            };
            errdefer releaseOne(top_idx);

            const og = index_at.get();
            defer releaseOne(og);
            Pool.global.sync();

            // -> CRITICAL SECTION
            index_at.set(top_idx);
            Pool.global.sync();
            // <- CRITICAL SECTION
        },
    }
}

pub fn get(_path: []const u8) !?Mode {
    var path = _path;
    if (path.len == 0) return null;
    var node = try fromIdx(Pool.global.block().root);

    blk: switch (node.next(path)) {
        .this => |idx| {
            if (node.bitset.isSet(idx)) {
                const sub = try node.indexAt(idx).getNode();
                if (sub.data == .midway) return null;
                return sub.data;
            } else {
                const val = node.indexAt(idx).get();
                if (val == 0) return null;
                return @bitCast(@as(u8, @truncate(val)));
            }
        },
        .next => |idx| {
            if (!node.bitset.isSet(idx)) return null;
            path = path[node.radix_len + 1 ..];
            node = try node.indexAt(idx).getNode();
            continue :blk node.next(path);
        },
        .diff => {
            return null;
        },
    }
}

pub fn del(_path: []const u8) !Mode {
    std.debug.assert(_path.len != 0);
    const b = Pool.global.block();
    var path = _path;
    var index_at_buf: [3]u8 = undefined;
    std.mem.writeInt(u24, &index_at_buf, @intCast(b.root), native_endian);
    var index_at: Node.IndexAt = .{ .at = 0, .arr = @ptrCast(&index_at_buf) };
    defer b.root = std.mem.readInt(u24, &index_at_buf, native_endian);
    var node = index_at.getNode() catch unreachable;
    var right_node_idx: ?u8 = null;

    blk: switch (node.next(path)) {
        .this => |idx| {
            // Delete the data
            const old_data: Mode = init: {
                if (node.bitset.isSet(idx)) {
                    const sub_idx = node.indexAt(idx).get();
                    const sub = try fromIdx(sub_idx);
                    if (sub.data == .midway) return error.NotFound;
                    const old = sub.data;
                    sub.data = .midway;

                    // If sub is empty, remove it from node
                    if (sub.valcntbounded(1) == 0) {
                        // -> CRITICAL SECTION
                        node.bitset.unset(idx);
                        node.indexAt(idx).set(0);
                        // <- CRITICAL SECTION
                        releaseOne(sub_idx);
                    }
                    break :init old;
                } else {
                    const val = node.indexAt(idx).get();
                    if (val == 0) return error.NotFound;
                    node.indexAt(idx).set(0);
                    break :init @bitCast(@as(u8, @truncate(val)));
                }
            };

            // Prune `node` if it's empty and not the top node
            if (right_node_idx) |r_idx| {
                if (node.data == .midway and node.valcntbounded(1) == 0) {
                    const top_node = try index_at.getNode();
                    const right_idx = top_node.indexAt(r_idx).get();
                    // -> CRITICAL SECTION
                    top_node.bitset.unset(r_idx);
                    top_node.indexAt(r_idx).set(0);
                    // <- CRITICAL SECTION
                    releaseLine(right_idx, false);
                }
            }

            // Check top_node for merge or prune
            const top_node = try index_at.getNode();
            const top_valcnt = top_node.valcntbounded(2);

            if (top_node.data == .midway and top_valcnt == 0) {
                // removed the very last node
                std.debug.assert(@intFromPtr(index_at.arr) == @intFromPtr(&index_at_buf));
                return old_data;
            }

            // Top node has data
            if (top_node.data != .midway or top_valcnt != 1) return old_data;

            // Merge top_node with its single remaining child
            const child = top_node.findFirstChild() orelse unreachable;
            const left_byte_idx = child.idx;

            if (!child.is_node) {
                const child_data: Mode = @bitCast(@as(u8, @truncate(child.val)));
                if (top_node.radix_len + 1 > top_node.radix_str.len) {
                    return old_data;
                }
                top_node.radix_str[top_node.radix_len] = left_byte_idx;

                // -> CRITICAL SECTION
                top_node.data = child_data;
                top_node.radix_len += 1;
                top_node.indexAt(left_byte_idx).set(0);
                // <- CRITICAL SECTION

                return old_data;
            }

            const left_node_idx = child.val;
            const left_node = try fromIdx(left_node_idx);

            const top_len = top_node.radix_len;
            const left_len = left_node.radix_len;
            const new_len = @as(usize, top_len) + 1 + left_len;

            if (new_len <= left_node.radix_str.len) {
                const old_top_idx = index_at.get();

                // -> CRITICAL SECTION
                const offset = top_len + 1;
                std.mem.copyBackwards(u8, left_node.radix_str[offset .. offset + left_len], left_node.radix_str[0..left_len]);
                @memcpy(left_node.radix_str[0..top_len], top_node.radix_str[0..top_len]);
                left_node.radix_str[top_len] = left_byte_idx;
                left_node.radix_len = @intCast(new_len);
                index_at.set(left_node_idx);
                // <- CRITICAL SECTION

                releaseOne(old_top_idx);
                return old_data;
            }

            // TODO: we can and should merge this [shift strings up in a chain of these ] but skipping it for now
            // Implementation: Shift as many bytes as possible from left_node up to top_node
            // const capacity = top_node.radix_str.len;
            // if (top_len < capacity) {
            //     const absorb = capacity - top_len;
            //     const K = absorb - 1;
            //     const actual_K = @min(K, left_len);
            //
            //     top_node.radix_str[top_len] = left_byte_idx;
            //     @memcpy(top_node.radix_str[top_len + 1 .. top_len + 1 + actual_K], left_node.radix_str[0..actual_K]);
            //     top_node.radix_len = top_len + 1 + actual_K;
            //
            //     top_node.bitset.unset(left_byte_idx);
            //     top_node.indexAt(left_byte_idx).set(0);
            //
            //     const new_left_byte_idx = left_node.radix_str[actual_K];
            //     top_node.bitset.set(new_left_byte_idx);
            //     top_node.indexAt(new_left_byte_idx).set(left_node_idx);
            //
            //     const new_left_len = left_len - (actual_K + 1);
            //     std.mem.copyForwards(u8, left_node.radix_str[0..new_left_len], left_node.radix_str[actual_K + 1 .. left_len]);
            //     left_node.radix_len = @intCast(new_left_len);
            // }
            return old_data;
        },
        .next => |idx| {
            if (!node.bitset.isSet(idx)) {
                @branchHint(.cold);
                return error.NotFound;
            }

            const valcnt = node.valcntbounded(2);
            if (valcnt > 1 or (valcnt == 1 and node.data != .midway)) {
                // Update top node (index_at) ONLY if current node is a fork or has data
                index_at = node.indexAt(idx);
                right_node_idx = null;
            } else if (right_node_idx == null) {
                // Node has 1 child and no data. Top node stays, right node is this child.
                right_node_idx = idx;
            }

            path = path[node.radix_len + 1 ..];
            node = try node.indexAt(idx).getNode();
            continue :blk node.next(path);
        },
        .diff => {
            @branchHint(.cold);
            return error.NotFound;
        },
    }
}

/// Acquire a brand new node from the pool and init it with the required values
fn acquire() !u24 {
    const node_idx = try Pool.global.acquire();
    const node = fromIdx(node_idx) catch unreachable;
    node.* = .{};
    return node_idx;
}

/// Release the node to the pool; does Not release all the nodes; only this one
fn releaseOne(idx: u24) void {
    Pool.global.release(idx);
}

fn fromIdx(idx: u24) Pool.OOB!*Node {
    return Pool.global.nodeAt(idx);
}

/// Releases a whole line of nodes starting from `start_idx`.
/// Assumes every node in the chain has exactly 1 child, except the last one which has 0.
fn releaseLine(start_idx: u24, comptime assert_inbounds: bool) if (assert_inbounds) void else (Pool.OOB || PathTooLong)!void {
    var curr_idx = start_idx;
    while (true) {
        const node = if (assert_inbounds) fromIdx(curr_idx) catch unreachable else try fromIdx(curr_idx);
        const count = node.bitset.count();
        if (count == 0) { // Reached the end of the line
            @branchHint(.unlikely);
            Pool.global.release(curr_idx);
            break;
        } else if (count > 1) { // If we encounter a fork in the "line", something went wrong.
            @branchHint(.cold);
            if (assert_inbounds) unreachable else return error.PathTooLong;
        } else { // count == 1: find the single child, release current, and step down
            @branchHint(.likely);
            const child_byte = @as(u8, @intCast(node.bitset.findFirstSet().?));
            const next_idx = node.indexAt(child_byte).get();
            Pool.global.release(curr_idx);
            curr_idx = next_idx;
        }
    }
}

pub const Node = extern struct {
    /// radix string length
    radix_len: u8 = 0,
    /// The data associated with the current node
    data: Mode = .midway,
    /// the actual storage for radix string
    radix_str: [children_count - 2 - (8 * 4)]u8 = undefined,
    /// If n't bit is set means nt'h index has an actual subnode; otherwise it's data
    bitset: Bitset = .empty,
    /// The indexes to the sub-nodes; 24 bits each
    idx_arr: [children_count * 3]u8 = [_]u8{0} ** (children_count * 3),

    comptime {
        std.debug.assert(@sizeOf(@This()) == 1 << 10);
    }

    const Bitset = std.bit_set.ArrayBitSet(u64, children_count);

    const IndexAt = struct {
        arr: *[children_count * 3]u8,
        at: u16,

        pub fn get(me: @This()) u24 {
            return std.mem.readInt(u24, me.arr[me.at..][0..3], native_endian);
        }

        pub fn getNode(me: @This()) !*Node {
            return fromIdx(me.get());
        }

        pub fn set(me: @This(), val: u24) void {
            return std.mem.writeInt(u24, me.arr[me.at..][0..3], val, native_endian);
        }
    };
    pub fn indexAt(self: *@This(), at: u8) IndexAt {
        return .{ .arr = &self.idx_arr, .at = @as(u16, at) * 3 };
    }

    const Next = union(enum) {
        /// The child in the nodes `this` idx is the one you want
        this: u8,
        /// What you want is is the subnode at idx `next`
        next: u8,
        /// There was a difference bw the node's radix_str and your path at idx `diff`
        diff: u8,
    };
    fn next(self: *@This(), path: []const u8) Next {
        if (path.len == 1) {
            @branchHint(.unlikely);
            if (self.radix_len == 0) return .{ .this = path[0] };
            return .{ .diff = 0 };
        }
        const maybe_consumed = mem.findDiff(u8, self.radix_str[0..self.radix_len], path[0 .. path.len - 1]);
        if (maybe_consumed == null) return .{ .this = path[path.len - 1] };

        const consumed = maybe_consumed.?;
        if (consumed == self.radix_len) return .{ .next = path[self.radix_len] };
        return .{ .diff = consumed };
    }

    fn valcntbounded(self: *@This(), comptime less_than: comptime_int) u8 {
        var bitsetcnt: u8 = self.bitset.count();
        if (bitsetcnt >= less_than) return less_than;
        for (0..children_count) |i| {
            if (!self.bitset.isSet(i) and self.indexAt(@intCast(i)).get() != 0) {
                bitsetcnt += 1;
                if (bitsetcnt >= less_than) {
                    @branchHint(.unlikely);
                    return less_than;
                }
            }
        }
        return bitsetcnt;
    }

    /// Finds the first child (subnode or inline data)
    pub fn findFirstChild(self: *@This()) ?struct { idx: u8, is_node: bool, val: u24 } {
        if (self.bitset.findFirstSet()) |i| {
            const idx: u8 = @intCast(i);
            return .{ .idx = idx, .is_node = true, .val = self.indexAt(idx).get() };
        }
        for (0..children_count) |i| {
            const val = self.indexAt(@intCast(i)).get();
            if (val != 0) {
                return .{ .idx = @intCast(i), .is_node = false, .val = val };
            }
        }
        return null;
    }
};

const PathTooLong = error{
    /// The file was invalid or had overlong path.
    /// the only valid reason for this to happen is if the file was created by a version that supports longer paths.
    PathTooLong,
};

pub const BlkIdx = packed struct(u32) {
    chr: u8,
    blk: u24,

    pub fn int(self: @This()) u32 {
        return @as(u32, @bitCast(self));
    }
};

pub const Mode = packed struct(u8) {
    /// Dicatates the kind of node
    k: K,
    /// Controls weather one can read the contents of the current dir or not.
    /// Default value depends on weather this is a dir or a file.
    r: A,
    /// Controls the write permission to the given file or dir.
    /// Allowing writes for dirs means renaming files; defaults to tracking file moves
    w: W,
    /// Controls weather exec is allowed. Disallowing this for a dir means the process can't read subdiles/subdirs
    x: A,

    pub const midway: @This() = @bitCast(@as(u8, 0));
    pub const dir: @This() = .{ .k = .visible_raw, .r = .allow, .w = .overlay, .x = .allow };
    pub const file: @This() = .{ .k = .visible_raw, .r = .deny, .w = .overlay, .x = .allow };

    pub const K = enum(u2) {
        /// This is a mid-way node and does not have it's own data; may or may not have children
        midway = 0,
        /// The file/dir is visible and present in the original fs
        visible_raw = 1,
        /// The file/dir is purely virtual; you should not do actual fs lookup in any case
        visible_virtual = 2,
        /// The node is not visible, may be created virtually in which case it will ve virtual
        invisible = 3,
    };
    pub const A = enum(u2) {
        deny = 0,
        ask = 1,
        allow = 2,
        _reserved,
    };
    pub const W = enum(u2) {
        deny = 0,
        ask = 1,
        allow = 2,
        overlay = 3,
    };
};
// Helper to compare packed structs safely
fn expectModeEqual(expected: Mode, actual: Mode) !void {
    try std.testing.expectEqual(@as(u8, @bitCast(expected)), @as(u8, @bitCast(actual)));
}

test "trie procedural forward and backward insertion/deletion" {
    const gpa = std.testing.allocator;

    // Generate all paths with chars 'a' and 'b' up to length 5
    // Total paths: 2^1 + 2^2 + 2^3 + 2^4 + 2^5 = 62 paths
    var paths: [62][]const u8 = undefined;
    var idx: usize = 0;
    for (1..6) |len| {
        const states = @as(usize, 1) << len;
        for (0..states) |mask| {
            const path = try gpa.alloc(u8, len);
            for (0..len) |i| {
                path[i] = if ((mask & (@as(usize, 1) << @intCast(i))) != 0) 'a' else 'b';
            }
            paths[idx] = path;
            idx += 1;
        }
    }
    defer for (paths) |p| gpa.free(p);

    // ==========================================
    // 1. Forward Insertion
    // ==========================================
    for (paths) |p| {
        try add(p, Mode.dir);
    }

    // Verify all were inserted
    for (paths) |p| {
        const res = try get(p);
        try std.testing.expect(res != null);
        try expectModeEqual(Mode.dir, res.?);
    }

    // ==========================================
    // 2. Selective Deletion from the Middle
    // ==========================================
    // Delete every 3rd path to force arbitrary middle deletions and merges
    for (0..paths.len) |i| {
        if (i % 3 == 0) {
            _ = try del(paths[i]);
        }
    }

    // Verify deleted are gone, and others remain
    for (0..paths.len) |i| {
        const res = try get(paths[i]);
        if (i % 3 == 0) {
            try std.testing.expectEqual(@as(?Mode, null), res);
        } else {
            try std.testing.expect(res != null);
            try expectModeEqual(Mode.dir, res.?);
        }
    }

    // ==========================================
    // 3. Re-add Deleted Paths with Different Mode
    // ==========================================
    for (0..paths.len) |i| {
        if (i % 3 == 0) {
            try add(paths[i], Mode.file);
        }
    }

    for (0..paths.len) |i| {
        const res = try get(paths[i]);
        if (i % 3 == 0) {
            try std.testing.expect(res != null);
            try expectModeEqual(Mode.file, res.?);
        } else {
            try std.testing.expect(res != null);
            try expectModeEqual(Mode.dir, res.?);
        }
    }

    // ==========================================
    // 4. Delete All Forward
    // ==========================================
    for (paths) |p| {
        _ = try del(p);
    }

    for (paths) |p| {
        try std.testing.expectEqual(@as(?Mode, null), try get(p));
    }

    // ==========================================
    // 5. Backward Insertion
    // ==========================================
    var i: usize = paths.len;
    while (i > 0) {
        i -= 1;
        try add(paths[i], Mode.dir);
    }

    // Verify all were inserted backward
    i = paths.len;
    while (i > 0) {
        i -= 1;
        const res = try get(paths[i]);
        try std.testing.expect(res != null);
        try expectModeEqual(Mode.dir, res.?);
    }

    // ==========================================
    // 6. Delete All Backward (with survivor checks)
    // ==========================================
    i = paths.len;
    while (i > 0) {
        i -= 1;
        _ = try del(paths[i]);
        
        // Ensure the deleted one is gone
        try std.testing.expectEqual(@as(?Mode, null), try get(paths[i]));
        
        // Ensure all previous items in the array still exist
        for (0..i) |j| {
            const res = try get(paths[j]);
            try std.testing.expect(res != null);
            try expectModeEqual(Mode.dir, res.?);
        }
    }
}

test "trie exhaustive subsets (add, get, overwrite, del)" {
    const gpa = std.testing.allocator;

    // Generate all paths with chars 'a' and 'b' up to length 3
    // Total paths: 2^1 + 2^2 + 2^3 = 14
    var paths: [14][]const u8 = undefined;
    var idx: usize = 0;
    for (1..4) |len| {
        const states = @as(usize, 1) << len;
        for (0..states) |mask| {
            const path = try gpa.alloc(u8, len);
            for (0..len) |i| {
                path[i] = if ((mask & (@as(usize, 1) << @intCast(i))) != 0) 'a' else 'b';
            }
            paths[idx] = path;
            idx += 1;
        }
    }
    defer for (paths) |p| gpa.free(p);
    
    // Test all possible subsets of these paths (2^14 = 16384 subsets)
    const total_sets = @as(usize, 1) << 14;
    for (0..total_sets) |set_mask| {
        
        // 1. Add all paths in this subset
        for (paths, 0..) |p, i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try add(p, Mode.dir);
            }
        }
        
        // 2. Overwrite all paths in this subset with a different mode
        for (paths, 0..) |p, i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try add(p, Mode.file);
            }
        }

        // 3. Verify gets
        for (paths, 0..) |p, i| {
            const res = try get(p);
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try std.testing.expect(res != null);
                try expectModeEqual(Mode.file, res.?);
            } else {
                try std.testing.expectEqual(@as(?Mode, null), res);
            }
        }
        
        // 4. Delete all paths in this subset
        for (paths, 0..) |p, i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                const old = try del(p);
                try expectModeEqual(Mode.file, old);
            }
        }
        
        // 5. Verify all are null after deletion
        for (paths) |p| {
            const res = try get(p);
            try std.testing.expectEqual(@as(?Mode, null), res);
        }
    }
}

test "trie deep path chains (length 4)" {
    const gpa = std.testing.allocator;

    // Generate all paths up to length 4 (2+4+8+16 = 30 paths)
    var paths: [30][]const u8 = undefined;
    var idx: usize = 0;
    for (1..5) |len| {
        const states = @as(usize, 1) << len;
        for (0..states) |mask| {
            const path = try gpa.alloc(u8, len);
            for (0..len) |i| {
                path[i] = if ((mask & (@as(usize, 1) << @intCast(i))) != 0) 'a' else 'b';
            }
            paths[idx] = path;
            idx += 1;
        }
    }
    defer for (paths) |p| gpa.free(p);

    // Add all deep paths
    for (paths) |p| {
        try add(p, Mode.dir);
    }

    // Verify all exist
    for (paths) |p| {
        const res = try get(p);
        try std.testing.expect(res != null);
        try expectModeEqual(Mode.dir, res.?);
    }

    // Delete in forward order (shortest to longest)
    for (paths) |p| {
        _ = try del(p);
        const res = try get(p);
        try std.testing.expectEqual(@as(?Mode, null), res);
    }
    
    // Re-add and delete in reverse order (longest to shortest)
    for (paths) |p| {
        try add(p, Mode.file);
    }
    
    var i: usize = paths.len;
    while (i > 0) {
        i -= 1;
        _ = try del(paths[i]);
        const res = try get(paths[i]);
        try std.testing.expectEqual(@as(?Mode, null), res);
        
        // Ensure earlier items still exist
        for (0..i) |j| {
            const r = try get(paths[j]);
            try std.testing.expect(r != null);
            try expectModeEqual(Mode.file, r.?);
        }
    }
}

test "trie edge cases and merges" {
    // Test adding and removing paths that cause repeated splits and merges
    const p1 = "a";
    const p2 = "ab";
    const p3 = "aba";
    const p4 = "abab";
    const p5 = "ababa";

    try add(p1, Mode.dir);
    try add(p2, Mode.dir);
    try add(p3, Mode.dir);
    try add(p4, Mode.dir);
    try add(p5, Mode.dir);

    // Delete from the middle
    _ = try del(p3);
    try std.testing.expectEqual(@as(?Mode, null), try get(p3));
    try std.testing.expect(try get(p4) != null);
    try std.testing.expect(try get(p5) != null);

    // Re-add it
    try add(p3, Mode.file);
    try std.testing.expect(try get(p3) != null);

    // Delete all
    _ = try del(p1);
    _ = try del(p2);
    _ = try del(p3);
    _ = try del(p4);
    _ = try del(p5);

    try std.testing.expectEqual(@as(?Mode, null), try get(p1));
    try std.testing.expectEqual(@as(?Mode, null), try get(p2));
    try std.testing.expectEqual(@as(?Mode, null), try get(p3));
    try std.testing.expectEqual(@as(?Mode, null), try get(p4));
    try std.testing.expectEqual(@as(?Mode, null), try get(p5));
}
