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
    var path = _path;

    if (Pool.global.block().root == 0) {
        @branchHint(.cold);
        const new_idx = try create(path, data, 0);
        Pool.global.block().root = new_idx;
        try Pool.global.sync();
        return;
    }

    var curr_idx: u24 = @intCast(Pool.global.block().root);
    var parent_idx: u24 = 0;
    var parent_byte: u8 = 0;
    var curr = try fromIdx(curr_idx);

    while (true) switch (curr.next(path)) {
        .exact => {
            curr.data = data;
            try Pool.global.sync();
            return;
        },
        .this => |idx| {
            if (curr.bitset.isSet(idx)) {
                const next = try curr.indexAt(idx).getNode();
                next.data = data;
            } else {
                curr.indexAt(idx).set(modeToInline(data));
            }
            try Pool.global.sync();
            return;
        },
        .next => |idx| {
            path = path[curr.radix_len + 1 ..];

            if (!curr.bitset.isSet(idx)) {
                const inline_val = curr.indexAt(idx).get();
                const new_idx = try create(path, data, inline_val);
                curr = try fromIdx(curr_idx);
                curr.bitset.set(idx);
                curr.indexAt(idx).set(new_idx);
                try Pool.global.sync();
                return;
            }

            parent_idx = curr_idx;
            parent_byte = idx;
            curr_idx = curr.indexAt(idx).get();
            curr = try fromIdx(curr_idx);
        },
        .diff => |idx| {
            const ogpath = path;
            const left_idx = try acquire();
            errdefer Pool.global.release(left_idx) catch {};
            var left = try fromIdx(left_idx);
            curr = try fromIdx(curr_idx);
            
            left.radix_len = curr.radix_len - idx - 1;
            left.data = curr.data;
            @memcpy(left.radix_str[0..left.radix_len], curr.radix_str[idx + 1 .. curr.radix_len]);
            left.bitset = curr.bitset;
            left.idx_arr = curr.idx_arr;

            const top_idx = try acquire();
            errdefer Pool.global.release(top_idx) catch {};
            var top = try fromIdx(top_idx);
            curr = try fromIdx(curr_idx);
            
            top.radix_len = idx;
            top.data = .midway;
            @memcpy(top.radix_str[0..idx], curr.radix_str[0..idx]);
            top.bitset.set(curr.radix_str[idx]);
            top.indexAt(curr.radix_str[idx]).set(left_idx);

            top = try fromIdx(top_idx);
            if (idx == ogpath.len) {
                top.data = data;
            } else {
                const new_path = ogpath[idx + 1 ..];
                if (new_path.len != 0) {
                    const right_idx = try create(new_path, data, 0);
                    top.bitset.set(ogpath[idx]);
                    top.indexAt(ogpath[idx]).set(right_idx);
                } else {
                    top.indexAt(ogpath[idx]).set(modeToInline(data));
                }
            }

            if (parent_idx == 0) {
                Pool.global.block().root = top_idx;
            } else {
                var parent_node = try fromIdx(parent_idx);
                parent_node.indexAt(parent_byte).set(top_idx);
            }

            try Pool.global.sync();
            try Pool.global.release(curr_idx);
            return;
        },
    };
}

fn create(path: []const u8, data: Mode, inline_val: u24) !u24 {
    const new_idx = try acquire();
    errdefer releaseLine(new_idx, true);
    
    var current_idx = new_idx;
    var current = try fromIdx(current_idx);
    current.data = if (inline_val == 0) .midway else inlineToMode(inline_val);

    var curr_path = path;
    if (inline_val != 0) {
        current.radix_len = 0;
        const next_byte = curr_path[0];
        curr_path = curr_path[1..];
        
        if (curr_path.len == 0) {
            current.indexAt(next_byte).set(modeToInline(data));
            return new_idx;
        }
        
        const new_next = try acquire();
        current = try fromIdx(current_idx);
        current.bitset.set(next_byte);
        current.indexAt(next_byte).set(new_next);
        
        current_idx = new_next;
        current = try fromIdx(current_idx);
        current.data = .midway;
    }

    while (true) {
        current.radix_len = @min(curr_path.len - 1, current.radix_str.len);
        @memcpy(current.radix_str[0..current.radix_len], curr_path[0..current.radix_len]);

        const next_byte = curr_path[current.radix_len];
        curr_path = curr_path[current.radix_len + 1 ..];
        
        if (curr_path.len == 0) {
            current.indexAt(next_byte).set(modeToInline(data));
            return new_idx;
        }

        const new_next = try acquire();
        current = try fromIdx(current_idx);
        current.bitset.set(next_byte);
        current.indexAt(next_byte).set(new_next);

        current_idx = new_next;
        current = try fromIdx(current_idx);
        current.data = .midway;
    }
}

pub fn del(_path: []const u8) !Mode {
    std.debug.assert(_path.len != 0);
    if (Pool.global.block().root == 0) {
        @branchHint(.cold);
        return error.NotFound;
    }
    
    var path = _path;

    var curr_idx: u24 = @intCast(Pool.global.block().root);
    var curr = try fromIdx(curr_idx);

    var parent_idx: u24 = 0;
    var parent_byte: u8 = 0;

    var top_idx: u24 = curr_idx;
    var top_parent_idx: u24 = 0;
    var top_parent_byte: u8 = 0;
    var top_child_byte: ?u8 = null;

    const old_data: Mode = del: {
        while (true) {
            switch (curr.next(path)) {
                .exact => {
                    if (@as(u8, @bitCast(curr.data)) == 0) return error.NotFound;
                    const old = curr.data;
                    curr.data = .midway;
                    break :del old;
                },
                .this => |idx| {
                    if (curr.bitset.isSet(idx)) {
                        const sub_idx = curr.indexAt(idx).get();
                        const sub = try fromIdx(sub_idx);
                        if (@as(u8, @bitCast(sub.data)) == 0) return error.NotFound;
                        const old = sub.data;
                        sub.data = .midway;

                        if (isEmpty(sub)) {
                            curr.bitset.unset(idx);
                            curr.indexAt(idx).set(0);
                            Pool.global.release(sub_idx) catch return error.CorruptedTrie;
                        }
                        break :del old;
                    } else {
                        const val = curr.indexAt(idx).get();
                        if (val == 0) return error.NotFound;
                        curr.indexAt(idx).set(0);
                        break :del inlineToMode(val);
                    }
                },
                .next => |idx| {
                    if (!curr.bitset.isSet(idx)) return error.NotFound;

                    const valcnt = curr.valcntbounded(2);
                    if (valcnt > 1 or (valcnt == 1 and @as(u8, @bitCast(curr.data)) != 0)) {
                        top_parent_idx = parent_idx;
                        top_parent_byte = parent_byte;
                        top_idx = curr_idx;
                        top_child_byte = idx;
                    } else if (top_child_byte == null) {
                        top_child_byte = idx;
                    }

                    parent_idx = curr_idx;
                    parent_byte = idx;

                    path = path[curr.radix_len + 1 ..];
                    curr_idx = curr.indexAt(idx).get();
                    curr = try fromIdx(curr_idx);
                    continue;
                },
                .diff => return error.NotFound,
            }
        }
    };

    // Determine the highest non-empty node (p_idx) and its parent
    var p_idx: u24 = 0;
    var p_parent_idx: u24 = 0;
    var p_parent_byte: u8 = 0;

    if (!isEmpty(curr)) {
        p_idx = curr_idx;
        if (curr_idx == top_idx) {
            p_parent_idx = top_parent_idx;
            p_parent_byte = top_parent_byte;
        } else {
            p_parent_idx = top_idx;
            p_parent_byte = top_child_byte orelse 0;
        }
    } else if (curr_idx == top_idx) {
        // top_idx itself is empty.
        if (top_parent_idx != 0) {
            const top_parent = try fromIdx(top_parent_idx);
            top_parent.bitset.unset(top_parent_byte);
            top_parent.indexAt(top_parent_byte).set(0);
            Pool.global.sync() catch {};
            Pool.global.release(top_idx) catch return error.CorruptedTrie;
        } else {
            // The root itself is empty. Release it and set root to 0.
            Pool.global.sync() catch {};
            Pool.global.release(top_idx) catch return error.CorruptedTrie;
            Pool.global.block().root = 0;
            Pool.global.sync() catch {};
            return old_data;
        }
        return old_data; // No merge needed if the fork itself was pruned
    } else {
        // A descendant is empty. Snip the chain from top_node.
        const top_node = try fromIdx(top_idx);
        if (top_child_byte) |tcb| {
            const chain_head_idx = top_node.indexAt(tcb).get();
            top_node.bitset.unset(tcb);
            top_node.indexAt(tcb).set(0);
            Pool.global.sync() catch {};
            releaseLine(chain_head_idx, false) catch return error.CorruptedTrie;
        }
        p_idx = top_idx;
        p_parent_idx = top_parent_idx;
        p_parent_byte = top_parent_byte;
    }

    // If the root itself became empty (e.g., lost its last child), clear it.
    if (p_parent_idx == 0 and isEmpty(try fromIdx(p_idx))) {
        Pool.global.sync() catch {};
        Pool.global.release(p_idx) catch return error.CorruptedTrie;
        Pool.global.block().root = 0;
        Pool.global.sync() catch {};
        return old_data;
    }

    const prune_node = try fromIdx(p_idx);

    // Rule A: Demote inline data promotion
    if (prune_node.valcntbounded(1) == 0 and @as(u8, @bitCast(prune_node.data)) != 0 and prune_node.radix_len == 0) {
        if (p_parent_idx != 0) {
            const parent_node = try fromIdx(p_parent_idx);
            parent_node.bitset.unset(p_parent_byte);
            parent_node.indexAt(p_parent_byte).set(modeToInline(prune_node.data));
            Pool.global.sync() catch {};
            Pool.global.release(p_idx) catch return error.CorruptedTrie;
            return old_data;
        }
    }

    // Rule B: Standard string merge
    if (prune_node.valcntbounded(2) == 1 and @as(u8, @bitCast(prune_node.data)) == 0) {
        const child = prune_node.findFirstChild() orelse unreachable;
        if (child.is_node) {
            const child_byte = child.idx;
            const left_node_idx = child.val;
            const left_node = try fromIdx(left_node_idx);

            const top_len = prune_node.radix_len;
            const left_len = left_node.radix_len;
            const new_len = @as(usize, top_len) + 1 + left_len;

            if (new_len <= left_node.radix_str.len) {
                const offset = top_len + 1;
                std.mem.copyBackwards(u8, left_node.radix_str[offset .. offset + left_len], left_node.radix_str[0..left_len]);
                @memcpy(left_node.radix_str[0..top_len], prune_node.radix_str[0..top_len]);
                left_node.radix_str[top_len] = child_byte;
                left_node.radix_len = @intCast(new_len);

                if (p_parent_idx != 0) {
                    const parent_node = try fromIdx(p_parent_idx);
                    parent_node.indexAt(p_parent_byte).set(left_node_idx);
                } else {
                    Pool.global.block().root = left_node_idx;
                }
                Pool.global.sync() catch {};
                Pool.global.release(p_idx) catch return error.CorruptedTrie;
                return old_data;
            }
        }
    }

    Pool.global.sync() catch {};
    return old_data;
}

pub fn get(_path: []const u8) !?Mode {
    var path = _path;
    if (path.len == 0) return null;
    if (Pool.global.block().root == 0) {
        @branchHint(.cold);
        return null;
    }
    
    var node = try fromIdx(@intCast(Pool.global.block().root));

    while (true) switch (node.next(path)) {
        .exact => {
            if (@as(u8, @bitCast(node.data)) == 0) return null;
            return node.data;
        },
        .this => |idx| {
            if (node.bitset.isSet(idx)) {
                const sub = try node.indexAt(idx).getNode();
                if (@as(u8, @bitCast(sub.data)) == 0) return null;
                return sub.data;
            } else {
                const val = node.indexAt(idx).get();
                if (val == 0) return null;
                return inlineToMode(val);
            }
        },
        .next => |idx| {
            if (!node.bitset.isSet(idx)) return null;
            path = path[node.radix_len + 1 ..];
            node = try node.indexAt(idx).getNode();
        },
        .diff => return null,
    };
}

/// Acquire a brand new node from the pool and init it with the required values
inline fn acquire() !u24 {
    const node_idx = try Pool.global.acquire();
    const node = fromIdx(node_idx) catch unreachable;
    node.* = .{};
    return node_idx;
}

fn fromIdx(idx: u24) Pool.OOB!*Node {
    return Pool.global.nodeAt(idx);
}

inline fn modeToInline(data: Mode) u24 {
    return @as(u24, @as(u8, @bitCast(data)));
}

inline fn inlineToMode(val: u24) Mode {
    return @bitCast(@as(u8, @truncate(val)));
}

inline fn isEmpty(node: *Node) bool {
    return @as(u8, @bitCast(node.data)) == 0 and node.valcntbounded(1) == 0;
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
            Pool.global.release(curr_idx) catch |e| if (assert_inbounds) unreachable else return e;
            break;
        } else if (count > 1) { // If we encounter a fork in the "line", something went wrong.
            @branchHint(.cold);
            if (assert_inbounds) unreachable else return error.PathTooLong;
        } else { // count == 1: find the single child, release current, and step down
            @branchHint(.likely);
            const child_byte = @as(u8, @intCast(node.bitset.findFirstSet().?));
            const next_idx = node.indexAt(child_byte).get();
            Pool.global.release(curr_idx) catch |e| if (assert_inbounds) unreachable else return e;
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
        /// This node itself contains the data inline
        exact: void,
    };
    fn next(self: *@This(), path: []const u8) Next {
        const shortest = @min(path.len, self.radix_len);
        const maybe_consumed = mem.findDiff(u8, self.radix_str[0..shortest], path[0..shortest]);
        if (maybe_consumed) |consumed| {
            return .{ .diff = @intCast(consumed) };
        }
        if (path.len == self.radix_len) return .exact;
        if (path.len > self.radix_len) {
            if (path.len - self.radix_len == 1) {
                return .{ .this = path[self.radix_len] };
            } else {
                return .{ .next = path[self.radix_len] };
            }
        }
        return .{ .diff = @intCast(path.len) };
    }

    fn valcntbounded(self: *@This(), comptime less_than: comptime_int) u8 {
        var bitsetcnt = self.bitset.count();
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
        return @intCast(bitsetcnt);
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
    /// The trie itself is corrupted and requires repair
    CorruptedTrie,
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

const testing = std.testing;

// Helper to compare packed structs safely
fn expectModeEqual(expected: Mode, actual: Mode) !void {
    try testing.expectEqual(@as(u8, @bitCast(expected)), @as(u8, @bitCast(actual)));
}

fn ensurePoolInitialized() !void {
    const fd = try std.posix.memfd_create("permbox-test-pool", 0);
    Pool.global = try Pool.init(fd);
}

test "trie exhaustive subsets (add, get, overwrite, del)" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;

    // Generate all paths with chars 'a' and 'b' up to length 3
    // Total paths: 2^1 + 2^2 + 2^3 = 14 paths
    var paths: [14][]const u8 = undefined;
    var idx: usize = 0;
    for (1..4) |len| {
        const states = @as(usize, 1) << @as(u6, @intCast(len));
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
        for (0..14) |i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try add(paths[i], Mode.dir);
            }
        }

        // 2. Overwrite all paths in this subset with a different mode
        for (0..14) |i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try add(paths[i], Mode.file);
            }
        }

        // 3. Verify gets
        for (0..14) |i| {
            const res = try get(paths[i]);
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try testing.expect(res != null);
                try expectModeEqual(Mode.file, res.?);
            } else {
                try testing.expectEqual(@as(?Mode, null), res);
            }
        }

        // 4. Delete all paths in this subset
        for (0..14) |i| {
            if ((set_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                const old = try del(paths[i]);
                try expectModeEqual(Mode.file, old);
            }
        }

        // 5. Verify all are null after deletion
        for (0..14) |i| {
            const res = try get(paths[i]);
            try testing.expectEqual(@as(?Mode, null), res);
        }
    }
}

test "trie randomized fuzz test" {
    if (!builtin.fuzz) return error.SkipZigTest;
    try ensurePoolInitialized();
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    var ref = std.StringHashMap(Mode).init(gpa);
    defer ref.deinit();

    // Generate all paths of 'a' and 'b' up to length 5 (62 paths)
    var paths: [62][]const u8 = undefined;
    var idx: usize = 0;
    for (1..6) |len| {
        const states = @as(usize, 1) << @as(u6, @intCast(len));
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

    var i: usize = 0;
    while (i < 200_000) : (i += 1) {
        const path_idx = random.intRangeLessThan(usize, 0, paths.len);
        const path = paths[path_idx];
        const op = random.intRangeLessThan(u8, 0, 3);

        if (op == 0) {
            // Add dir
            try add(path, Mode.dir);
            try ref.put(path, Mode.dir);
        } else if (op == 1) {
            // Add file
            try add(path, Mode.file);
            try ref.put(path, Mode.file);
        } else {
            // Del
            if (ref.get(path)) |_| {
                _ = try del(path);
                _ = ref.remove(path);
            } else {
                try testing.expectError(error.NotFound, del(path));
            }
        }

        // Verify all paths against the reference map
        for (paths) |p| {
            const r = ref.get(p);
            const t = try get(p);
            if (r) |rv| {
                try testing.expect(t != null);
                try expectModeEqual(rv, t.?);
            } else {
                try testing.expectEqual(@as(?Mode, null), t);
            }
        }
    }
}

test "trie deep path string limit and partial shift" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;

    // The trie's radix_str capacity is 222 bytes.
    // We want to test the case where top_len + 1 + left_len > 222
    // Let's make top_len = 200, left_len = 30.
    // new_len = 231 > 222.

    const p1 = try gpa.alloc(u8, 200);
    defer gpa.free(p1);
    @memset(p1, 'a');

    const p2 = try gpa.alloc(u8, 231);
    defer gpa.free(p2);
    @memset(p2, 'a');
    p2[200] = 'b';
    @memset(p2[201..], 'a');

    const p3 = try gpa.alloc(u8, 231);
    defer gpa.free(p3);
    @memset(p3, 'a');
    p3[200] = 'c';
    @memset(p3[201..], 'a');

    try add(p1, Mode.dir);
    try add(p2, Mode.dir);
    try add(p3, Mode.dir);

    try expectModeEqual(Mode.dir, (try get(p1)).?);
    try expectModeEqual(Mode.dir, (try get(p2)).?);
    try expectModeEqual(Mode.dir, (try get(p3)).?);

    // Delete p2. This will trigger the partial shift logic
    // because top_len (200) + 1 + left_len (30) = 231 > 222
    _ = try del(p2);

    try testing.expectEqual(@as(?Mode, null), try get(p2));
    try expectModeEqual(Mode.dir, (try get(p1)).?);
    try expectModeEqual(Mode.dir, (try get(p3)).?);

    // Delete p1. This triggers the partial shift logic again
    _ = try del(p1);

    try testing.expectEqual(@as(?Mode, null), try get(p1));
    try expectModeEqual(Mode.dir, (try get(p3)).?);

    // Delete p3
    _ = try del(p3);
    try testing.expectEqual(@as(?Mode, null), try get(p3));
}

test "trie delete non-existent and empty" {
    try ensurePoolInitialized();
    try testing.expectError(error.NotFound, del("a"));

    try add("a", Mode.dir);
    try testing.expectError(error.NotFound, del("b"));
    try testing.expectError(error.NotFound, del("aa"));

    _ = try del("a");
    try testing.expectError(error.NotFound, del("a"));
}

test "trie procedural forward and backward insertion/deletion" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;

    // Generate all paths with chars 'a' and 'b' up to length 5
    // Total paths: 2^1 + 2^2 + 2^3 + 2^4 + 2^5 = 62 paths
    var paths: [62][]const u8 = undefined;
    var idx: usize = 0;
    for (1..6) |len| {
        const states = @as(usize, 1) << @as(u6, @intCast(len));
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
        try testing.expect(res != null);
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
            try testing.expectEqual(@as(?Mode, null), res);
        } else {
            try testing.expect(res != null);
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
            try testing.expect(res != null);
            try expectModeEqual(Mode.file, res.?);
        } else {
            try testing.expect(res != null);
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
        try testing.expectEqual(@as(?Mode, null), try get(p));
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
        try testing.expect(res != null);
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
        try testing.expectEqual(@as(?Mode, null), try get(paths[i]));

        // Ensure all previous items in the array still exist
        for (0..i) |j| {
            const res = try get(paths[j]);
            try testing.expect(res != null);
            try expectModeEqual(Mode.dir, res.?);
        }
    }
}

test "trie deep path chains (length 4)" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;

    // Generate all paths up to length 4 (2+4+8+16 = 30 paths)
    var paths: [30][]const u8 = undefined;
    var idx: usize = 0;
    for (1..5) |len| {
        const states = @as(usize, 1) << @as(u6, @intCast(len));
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
        try testing.expect(res != null);
        try expectModeEqual(Mode.dir, res.?);
    }

    // Delete in forward order (shortest to longest)
    for (paths) |p| {
        _ = try del(p);
        const res = try get(p);
        try testing.expectEqual(@as(?Mode, null), res);
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
        try testing.expectEqual(@as(?Mode, null), res);

        // Ensure earlier items still exist
        for (0..i) |j| {
            const r = try get(paths[j]);
            try testing.expect(r != null);
            try expectModeEqual(Mode.file, r.?);
        }
    }
}

test "trie edge cases and merges" {
    try ensurePoolInitialized();
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
    try testing.expectEqual(@as(?Mode, null), try get(p3));
    try testing.expect(try get(p4) != null);
    try testing.expect(try get(p5) != null);

    // Re-add it
    try add(p3, Mode.file);
    try testing.expect(try get(p3) != null);

    // Delete all
    _ = try del(p1);
    _ = try del(p2);
    _ = try del(p3);
    _ = try del(p4);
    _ = try del(p5);

    try testing.expectEqual(@as(?Mode, null), try get(p1));
    try testing.expectEqual(@as(?Mode, null), try get(p2));
    try testing.expectEqual(@as(?Mode, null), try get(p3));
    try testing.expectEqual(@as(?Mode, null), try get(p4));
    try testing.expectEqual(@as(?Mode, null), try get(p5));
}

// --- Permutation Helper ---
fn nextPermutation(comptime T: type, array: []T) bool {
    if (array.len <= 1) return false;
    var i: usize = array.len - 1;
    while (true) {
        const j = i;
        i -= 1;
        if (array[i] < array[j]) {
            var k = array.len - 1;
            while (array[i] >= array[k]) k -= 1;
            std.mem.swap(T, &array[i], &array[k]);
            std.mem.reverse(T, array[j..]);
            return true;
        }
        if (i == 0) {
            std.mem.reverse(T, array);
            return false;
        }
    }
}

// --- Structural & Allocation Invariants ---
fn checkAllocationInvariant() !void {
    const blk = Pool.global.block();
    if (blk.free_from > 2) {
        try testing.expect(blk.free_idx == 0 or blk.free_idx < blk.free_from);
    }
    try testing.expect(blk.root < blk.free_from);
}

fn checkStructuralInvariants() !void {
    const gpa = testing.allocator;
    var visited = std.AutoHashMap(u24, void).init(gpa);
    defer visited.deinit();

    const blk = Pool.global.block();
    try visitNode(@intCast(blk.root), &visited);

    // Count free list size
    var free_count: u32 = 0;
    var curr_free = blk.free_idx;
    while (curr_free != 0) {
        free_count += 1;
        const node = try Pool.global.nodeAt(@intCast(curr_free));
        curr_free = node.indexAt(0xfe).get();
    }

    // Total nodes = reachable (includes root) + free + 1 (block 0)
    try testing.expectEqual(@as(u32, @intCast(visited.count())) + free_count + 1, blk.free_from);
}

fn visitNode(idx: u24, visited: *std.AutoHashMap(u24, void)) !void {
    if (idx == 0) return;
    if (visited.contains(idx)) return error.CycleDetected;
    try visited.put(idx, {});

    const node = try Pool.global.nodeAt(idx);
    if (node.radix_len > node.radix_str.len) return error.RadixLenTooLarge;

    var iter = node.bitset.iterator(.{});
    while (iter.next()) |i| {
        const child_idx = node.indexAt(@intCast(i)).get();
        if (child_idx == 0) return error.BitSetChildIsZero;
        try visitNode(child_idx, visited);
    }
}

// --- 1. Exhaust every insertion permutation ---
test "1. exhaustive insertion permutations" {
    try ensurePoolInitialized();
    const paths = [_][]const u8{ "a", "ab", "aba", "abb", "abc" };
    var perm = [_]usize{ 0, 1, 2, 3, 4 };

    var first = true;
    while (first or nextPermutation(usize, &perm)) {
        first = false;
        // Clear trie
        for (paths) |p| _ = del(p) catch {};

        for (perm) |i| try add(paths[i], Mode.dir);
        for (paths) |p| try testing.expect(try get(p) != null);

        var j: usize = perm.len;
        while (j > 0) {
            j -= 1;
            _ = try del(paths[perm[j]]);
        }

        for (paths) |p| try testing.expectEqual(@as(?Mode, null), try get(p));

        try checkStructuralInvariants();
        try checkAllocationInvariant();
    }
}

// --- 2. Exhaust every delete permutation ---
test "2. exhaustive delete permutations" {
    try ensurePoolInitialized();
    const paths = [_][]const u8{ "a", "ab", "aba", "abb", "abc" };
    var perm = [_]usize{ 0, 1, 2, 3, 4 };

    for (paths) |p| try add(p, Mode.dir);

    var first = true;
    while (first or nextPermutation(usize, &perm)) {
        first = false;
        // Reset trie
        for (paths) |p| _ = del(p) catch {};
        for (paths) |p| try add(p, Mode.dir);

        for (perm) |i| {
            _ = try del(paths[i]);
        }

        for (paths) |p| try testing.expectEqual(@as(?Mode, null), try get(p));
        try checkStructuralInvariants();
        try checkAllocationInvariant();
    }
}

// --- 3. Exhaust every split point ---
test "3. exhaust every split point" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;

    for (0..30) |split_idx| {
        const p1 = try gpa.alloc(u8, 30);
        defer gpa.free(p1);
        @memset(p1, 'a');

        const p2 = try gpa.alloc(u8, 30);
        defer gpa.free(p2);
        @memset(p2, 'a');
        p2[split_idx] = 'b';

        try add(p1, Mode.dir);
        try add(p2, Mode.file);

        try expectModeEqual(Mode.dir, (try get(p1)).?);
        try expectModeEqual(Mode.file, (try get(p2)).?);

        _ = try del(p1);
        _ = try del(p2);

        try checkStructuralInvariants();
        try checkAllocationInvariant();
    }
}

// --- 4. Root replacement torture ---
test "4. root replacement torture" {
    try ensurePoolInitialized();
    const paths = [_][]const u8{ "a", "ab", "abc", "abcd", "abcde" };

    for (paths) |p| try add(p, Mode.dir);
    // Delete backwards
    var i = paths.len;
    while (i > 0) {
        i -= 1;
        _ = try del(paths[i]);
        try checkStructuralInvariants();
    }

    // Re-add and delete forwards
    for (paths) |p| try add(p, Mode.file);
    for (paths) |p| _ = try del(p);

    try checkStructuralInvariants();
    try checkAllocationInvariant();
}

// --- 5 & 8. Alternate split/merge (Oscillating tree) ---
test "5 & 8. alternate split/merge oscillating tree" {
    try ensurePoolInitialized();
    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        try add("a", Mode.dir);
        try add("ab", Mode.dir);
        try add("abc", Mode.dir);

        _ = try del("ab");
        try add("ab", Mode.file);

        _ = try del("a");
        try add("a", Mode.file);

        _ = try del("abc");
        try add("abc", Mode.file);

        if (i % 100 == 0) {
            try checkStructuralInvariants();
            try checkAllocationInvariant();
        }
    }
    _ = try del("a");
    _ = try del("ab");
    _ = try del("abc");
}

// --- 6. Every possible common prefix ---
test "6. every possible common prefix" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;
    const capacity = (Node{}).radix_str.len; // 222

    for (0..capacity + 1) |prefix_len| {
        const p1 = try gpa.alloc(u8, prefix_len + 1);
        defer gpa.free(p1);
        const p2 = try gpa.alloc(u8, prefix_len + 1);
        defer gpa.free(p2);

        @memset(p1[0..prefix_len], 'a');
        @memset(p2[0..prefix_len], 'a');
        p1[prefix_len] = 'X';
        p2[prefix_len] = 'Y';

        try add(p1, Mode.dir);
        try add(p2, Mode.file);

        try expectModeEqual(Mode.dir, (try get(p1)).?);
        try expectModeEqual(Mode.file, (try get(p2)).?);

        _ = try del(p1);
        _ = try del(p2);
    }
    try checkStructuralInvariants();
}

// --- 7. Long linear chain ---
test "7. long linear chain" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;
    var paths = std.ArrayList([]u8).empty;
    defer {
        for (paths.items) |p| gpa.free(p);
        paths.deinit(gpa);
    }

    // Create paths up to length 224
    for (1..225) |len| {
        const p = try gpa.alloc(u8, len);
        @memset(p, 'a');
        try paths.append(gpa, p);
    }

    for (paths.items) |p| try add(p, Mode.dir);

    // Delete from middle outward
    var low: usize = paths.items.len / 2;
    var high = low + 1;
    while (true) {
        _ = try del(paths.items[low]);
        if (high < paths.items.len) {
            _ = try del(paths.items[high]);
            high += 1;
        }
        if (low == 0) break;
        low -%= 1;
    }
    // Clean up the rest (should be none, but safe)
    for (paths.items) |p| _ = del(p) catch {};

    try checkStructuralInvariants();
}

// --- 9. Free list reuse ---
test "9. free list reuse" {
    try ensurePoolInitialized();
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        try add("a", Mode.dir);
        _ = try del("a");
    }
    // After oscillating, free_from should be exactly at the root + 1
    try testing.expectEqual(@as(u32, 2), Pool.global.block().free_from);
    try checkAllocationInvariant();
}

// --- 10. Maximum branching ---
test "10. maximum branching" {
    try ensurePoolInitialized();
    const gpa = testing.allocator;
    const paths = try gpa.alloc([]const u8, 256);
    defer gpa.free(paths);

    var buf: [1]u8 = undefined;
    for (0..256) |i| {
        buf[0] = @intCast(i);
        paths[i] = try gpa.dupe(u8, &buf);
    }
    defer for (paths) |p| gpa.free(p);

    for (paths) |p| try add(p, Mode.dir);
    try checkStructuralInvariants();

    // Delete forwards
    for (paths) |p| _ = try del(p);
    try checkStructuralInvariants();

    // Re-add and delete backwards
    for (paths) |p| try add(p, Mode.file);
    var i: usize = paths.len;
    while (i > 0) {
        i -= 1;
        _ = try del(paths[i]);
    }
    try checkStructuralInvariants();
}

// --- 11. Prefix/non-prefix combinations ---
test "11. prefix/non-prefix combinations" {
    try ensurePoolInitialized();
    const paths = [_][]const u8{ "a", "ab", "abc", "abcd", "abcde" };
    var perm = [_]usize{ 0, 1, 2, 3, 4 };

    const total_subsets = @as(usize, 1) << paths.len;
    for (0..total_subsets) |subset_mask| {
        // Insert subset
        for (0..paths.len) |i| {
            if ((subset_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                try add(paths[i], Mode.dir);
            }
        }

        // Delete in every permutation
        var first = true;
        while (first or nextPermutation(usize, &perm)) {
            first = false;
            // Re-insert if missing
            for (0..paths.len) |i| {
                if ((subset_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                    if (try get(paths[i]) == null) {
                        try add(paths[i], Mode.dir);
                    }
                }
            }

            for (perm) |i| {
                if ((subset_mask & (@as(usize, 1) << @intCast(i))) != 0) {
                    _ = try del(paths[i]);
                }
            }
        }
        try checkStructuralInvariants();
    }
}

// --- 12. Random long paths ---
test "12. random long paths" {
    if (!builtin.fuzz) return error.SkipZigTest;
    try ensurePoolInitialized();
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    var ref = std.StringHashMap(Mode).init(gpa);
    defer ref.deinit();

    var i: usize = 0;
    while (i < 50_000) : (i += 1) {
        const len = random.intRangeLessThan(usize, 1, 250);
        const path = try gpa.alloc(u8, len);
        defer gpa.free(path);
        for (path) |*c| c.* = random.int(u8);

        const op = random.intRangeLessThan(u8, 0, 3);
        if (op == 0 or op == 1) {
            const data: Mode = if (op == 0) Mode.dir else Mode.file;
            try add(path, data);
            // We can't easily put stack allocated slice in hashmap, so dupe it
            const owned = try gpa.dupe(u8, path);
            const gop = try ref.getOrPut(owned);
            if (gop.found_existing) gpa.free(owned) else gop.value_ptr.* = data;
            gop.value_ptr.* = data;
        } else {
            if (ref.fetchRemove(path)) |entry| {
                _ = try del(entry.key);
                gpa.free(entry.key);
            } else {
                try testing.expectError(error.NotFound, del(path));
            }
        }

        if (i % 1000 == 0) {
            try checkStructuralInvariants();
        }
    }

    // Cleanup
    var it = ref.iterator();
    while (it.next()) |entry| {
        _ = try del(entry.key_ptr.*);
        gpa.free(entry.key_ptr.*);
    }
    try checkStructuralInvariants();
}

// --- 13. Repeated overwrite ---
test "13. repeated overwrite" {
    try ensurePoolInitialized();
    // Pre-allocate the path's nodes so subsequent adds are pure overwrites
    try add("path", Mode.dir);
    const blk = Pool.global.block();
    const start_free_from = blk.free_from;

    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        try add("path", Mode.dir);
        try add("path", Mode.file);
        try add("path", Mode.dir);
    }

    // No new nodes should have been allocated
    try testing.expectEqual(start_free_from, blk.free_from);
    _ = try del("path");
}
