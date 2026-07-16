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
    const b = Pool.global.block();
    var path = _path;
    var index_at_buf: [3]u8 = undefined;
    std.mem.writeInt(u24, &index_at_buf, @intCast(b.root), native_endian);
    var index_at: Node.IndexAt = .{ .at = 0, .arr = @ptrCast(&index_at_buf) };
    var node = Node.fromIdx(index_at.get()) catch unreachable;

    blk: switch (node.next(path)) {
        .node => |idx| { // Go to next node
            path = path[node.radix_len + 1 ..];
            std.debug.assert(path.len != 0);
            index_at = node.indexAt(idx);
            node = try Node.fromIdx(index_at.get());
            continue :blk node.next(path);
        },
        .this => |idx| { // the entry already exists; only need to set data
            if (node.bitset.isSet(idx)) {
                const next = try Node.fromIdx(node.indexAt(idx).get());
                next.data = data;
            } else {
                node.indexAt(idx).set(data);
            }
        },
        .diff => |idx| {
            const ogpath = path;
            path = path[idx + 1 ..];

            const left_idx: u24 = init: {
                const new_idx = try Node.acquire();
                const new = Node.fromIdx(new_idx) catch unreachable;
                new.radix_len = node.radix_len - idx - 1;
                new.data = .midway;
                @memcpy(new.radix_str[0..new.radix_len], node.radix_str[idx + 1 ..]);
                const boff = @offsetOf(Node, "bitset");
                @memcpy(std.mem.asBytes(new)[boff..], std.mem.asBytes(node)[boff..]);
                break :init new_idx;
            };
            errdefer Node.releaseOne(left_idx);

            const need_right = path.len != 0;
            const right_idx: u24 = init: {
                if (!need_right) break :init 0;
                const new_idx = try Node.acquire();
                const new = Node.fromIdx(new_idx) catch unreachable;
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

                    const new_next = try Node.acquire();
                    current.bitset.set(next_idx);
                    current.indexAt(next_idx).set(new_next);
                    current = Node.fromIdx(new_next) catch unreachable;
                }
            };
            errdefer {
                if (need_right) Node.release(right_idx, true);
            }

            const top_idx: u24 = init: {
                const new_idx = try Node.acquire();
                const new = Node.fromIdx(new_idx) catch unreachable;
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
            errdefer Node.releaseOne(top_idx);

            const og = index_at.get();
            defer Node.releaseOne(og);
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
    var node = try Node.fromIdx(Pool.global.block().root);

    blk: switch (node.next(path)) {
        .this => |idx| {
            if (node.bitset.isSet(idx)) {
                const sub = try Node.fromIdx(node.indexAt(idx).get());
                return sub.data;
            } else {
                const val = node.indexAt(idx).get();
                if (val == 0) return null;
                return @enumFromInt(@as(u8, @intCast(val)));
            }
        },
        .next => |idx| {
            if (!node.bitset.isSet(idx)) return null;
            path = path[node.radix_len + 1 ..];
            node = try Node.fromIdx(node.indexAt(idx).get());
            continue :blk node.next(path);
        },
        .diff => {
            return null;
        },
    }
}

pub fn del(path: []const u8) !Mode {
    const b = Pool.global.block();
    var path = _path;
    var index_at_buf: [3]u8 = undefined;
    std.mem.writeInt(u24, &index_at_buf, @intCast(b.root), native_endian);
    var index_at: Node.IndexAt = .{ .at = 0, .arr = @ptrCast(&index_at_buf) };
    var node = Node.fromIdx(index_at.get()) catch unreachable;
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

        pub fn set(me: @This(), val: u24) void {
            return std.mem.writeInt(u24, &me.arr[me.at][0..3], val, native_endian);
        }
    };
    pub fn indexAt(self: *@This(), at: u8) IndexAt {
        return .{ .arr = &self.idx_arr, .at = at * 3 };
    }

    fn fromIdx(self: u24) Pool.OOB!*@This() {
        return Pool.global.nodeAt(self);
    }

    fn toIdx(self: *@This()) Pool.OOB!u24 {
        return Pool.global.indexOf(self);
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
        self.* = undefined;
        Pool.global.release(self);
    }

    fn release(idx: u24, comptime assert_inbounds: bool) if (assert_inbounds) void else (Pool.OOB || PathTooLong)!void {
        var stack: [max_depth]BlkIdx = undefined;
        stack[0] = .{ .chr = 0, .idx = idx };
        var len = 1;
        outer: while (len > 0) {
            const top = &stack[len - 1];
            const node = if (assert_inbounds) fromIdx(top.blk) catch unreachable else try fromIdx(top.blk);

            if (len == stack.len) {
                @branchHint(.cold);
                for (top.chr..0xff) |i| {
                    if (node.bitset.isSet(i)) {
                        const subidx = node.indexAt(@intCast(i)).get();

                        const subnode = if (assert_inbounds) fromIdx(subidx) catch unreachable else try fromIdx(subidx);
                        inline for (0..4) |j| {
                            if (subnode.bitset[j] != 0) {
                                if (assert_inbounds) unreachable;
                                return PathTooLong.PathTooLong;
                            }
                        }
                        Pool.global.release(subidx);
                    }
                }
            } else {
                for (top.chr..0xff) |i| {
                    if (node.bitset.isSet(i)) {
                        top.chr = @bitCast(i);
                        stack[len] = .{ .chr = 0, .blk = node.indexAt(@intCast(i)).get() };

                        len += 1;
                        continue :outer;
                    }
                }
            }

            const blk = top.blk;
            if (node.bitset.isSet(0xff)) {
                top.* = .{ .chr = 0, .blk = node.indexAt(0xff).get() };
            } else {
                len -= 1;
            }
            Pool.global.release(blk);
        }
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

    pub const midway: @This() = .{ .k = .midway, .r = undefined, .w = undefined, .x = undefined };
    pub const dir: @This() = .{ .k = .visible, .value = true, .r = .allow, .w = .overlay, .x = .allow };
    pub const file: @This() = .{ .k = .visible, .value = true, .r = .deny, .w = .overlay, .x = .allow };

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
