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
                node.indexAt(idx).set(data);
            }
        },
        .node => |idx| { // Go to next node
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
                new.data = .midway;
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
                    current.radix_len = @min(path.len - 1, node.radix_str.len);
                    current.data = .midway;
                    @memcpy(current.radix_str[0..current.radix_len], path[0..current.radix_len]);

                    const next_idx = path[current.radix_len];
                    path = path[current.radix_len + 1 ..];
                    if (path.len == 0) {
                        current.indexAt(next_idx).set(data);
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
                new.data = node.data;
                @memcpy(new.radix_str[0..idx], node.radix_str[0..idx]);
                new.bitset.set(left_idx);
                new.indexAt(node.radix_str[idx]).set(left_idx);

                if (need_right) {
                    new.bitset.set(right_idx);
                    new.indexAt(ogpath[idx]).set(right_idx);
                } else {
                    new.indexAt(idx).set(data);
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
                return sub.data;
            } else {
                const val = node.indexAt(idx).get();
                if (val == 0) return null;
                return @enumFromInt(@as(u8, @truncate(val)));
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
            // 1. Delete the data
            const old_data: Mode = init: {
                if (node.bitset.isSet(idx)) {
                    const sub_idx = node.indexAt(idx).get();
                    const sub = try fromIdx(sub_idx);
                    const old = sub.data;
                    sub.data = .midway;
                    break :init old;
                } else {
                    const val = node.indexAt(idx).get();
                    node.indexAt(idx).set(0);
                    break :init @enumFromInt(@as(u8, @truncate(val)));
                }
            };

            if (old_data == .midway) return error.NotFound;

            const top_node = try index_at.getNode();
            const r_idx = right_node_idx orelse init: {
                const ni = node.indexAt(idx);
                const n = try ni.getNode();
                if (!n.bitset.isSet(idx)) return old_data;
                const valcnt = n.valcntbounded(2);
                if (valcnt == 0) { // sus; maybe corrupted file
                    @branchHint(.cold);
                    const niv = ni.get();
                    // -> CRITICAL SECTION
                    node.bitset.unset(idx);
                    ni.set(0);
                    // <- CRITICAL SECTION
                    try releaseOne(niv, false);
                } else if (valcnt == 1) {
                    break :init idx;
                }
                return old_data;
            };

            if (node.data != .midway or node.valcntbounded(1) == 1) return old_data;
            // Because of our top_node rule, if `node` is empty, the ENTIRE chain
            // from `right_node` down to `node` is empty and can be removed!

            const right_idx = top_node.indexAt(r_idx).get();
            // -> CRITICAL SECTION
            top_node.bitset.unset(r_idx);
            top_node.indexAt(r_idx).set(0);
            // <- CRITICAL SECTION
            releaseLine(right_idx, false);

            if (top_node.data != .midway) return old_data;
            const topvalcnt = top_node.valcntbounded(2);
            std.debug.assert(topvalcnt != 0);
            if (topvalcnt != 1) return old_data;
            // If top node now has exactly 1 child and no data, we must merge it;

            if (@intFromPtr(index_at.arr) == @intFromPtr(&index_at_buf)) { // index_at was root
                @branchHint(.unlikely);
                // TODO
            } else { // Normal case
                // TODO
            }

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
            node = try fromIdx(node.indexAt(idx).get());
            continue :blk node.next();
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
fn releaseOne(self: u24) void {
    Pool.global.release(self);
}

fn fromIdx(self: u24) Pool.OOB!*@This() {
    return Pool.global.nodeAt(self);
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
    bitset: std.bit_set.ArrayBitSet(u64, 4) = .empty,
    /// The indexes to the sub-nodes; 24 bits each
    idx_arr: [children_count * 3]u8 = (children_count * 3) ** [_]u8{0},

    comptime {
        std.debug.assert(@sizeOf(@This()) == 1 << 10);
    }

    const IndexAt = struct {
        arr: *[children_count * 3]u8,
        at: u16,

        pub fn get(me: @This()) u24 {
            return std.mem.readInt(u24, &me.arr[me.at][0..3], native_endian);
        }

        pub fn getNode(me: @This()) !*Node {
            return fromIdx(me.get());
        }

        pub fn set(me: @This(), val: u24) void {
            return std.mem.writeInt(u24, &me.arr[me.at][0..3], val, native_endian);
        }
    };
    pub fn indexAt(self: *@This(), at: u8) IndexAt {
        return .{ .arr = &self.idx_arr, .at = at * 3 };
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
        const maybe_consumed = mem.findDiff(u8, self.radix_str[0..self.radix_len], path[0 .. path.len - 1]);
        if (maybe_consumed == null) return .{ .this = path[path.len - 1] };

        const consumed = maybe_consumed.?;
        if (consumed == self.radix_len) return .{ .next = path[self.radix_len] };
        return .{ .diff = consumed };
    }

    fn valcntbounded(self: *@This(), comptime less_than: comptime_int) u8 {
        const bitsetcnt: u8 = self.bitset.count();
        if (bitsetcnt >= less_than) return less_than;
        for (0..children_count) |i| {
            if (!self.bitset.isSet(i) and @as(u8, @truncate(self.indexAt(i).get())) != 0) {
                bitsetcnt += 1;
                if (bitsetcnt == less_than) {
                    @branchHint(.unlikely);
                    return less_than;
                }
            }
        }
        return bitsetcnt;
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
        return @bitCast(self);
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

    pub const midway: @This() = @bitCast(0);
    pub const dir: @This() = .{ .k = .visible, .r = .allow, .w = .overlay, .x = .allow };
    pub const file: @This() = .{ .k = .visible, .r = .deny, .w = .overlay, .x = .allow };

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
