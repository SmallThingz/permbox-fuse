//! This has the implementation of the trie that tracks the permissions
const std = @import("std");
const builtin = @import("builtin");
const mem = @import("mem.zig");
const Pool = @import("pool.zig");

const native_endian = builtin.cpu.arch.endian();
const children_count = 1 << 8;
const RadixInt = u8;

pub const BlkIdx = packed struct(u32) {
    chr: u8,
    blk: u24,

    pub fn int(self: @This()) u32 {
        return @bitCast(self);
    }
};

pub const Node = extern struct {
    /// radix string length
    radix_len: u8 = 0,
    /// The data associated with the current node
    data: Mode,
    /// the actual storage for radix string
    radix_str: [children_count - 2 - (8 * 4)]u8 = undefined,
    /// If n't bit is set means nt'h index has an actual subnode; otherwise it's data
    bitset: std.bit_set.ArrayBitSet(u64, 4) = .empty,
    /// The indexes to the sub-nodes; 24 bits each
    idx_arr: [children_count * 3]u8 = (children_count * 3) ** [_]u8{0},

    comptime {
        std.debug.assert(@sizeOf(@This()) == 1 << 10);
    }

    pub fn indexAt(self: *@This(), at: u8) struct {
        arr: *[children_count * 3]u8,
        at: u16,

        pub fn get(me: @This()) u24 {
            return std.mem.readInt(u24, &me.arr[me.at][0..3], native_endian);
        }

        pub fn set(me: @This(), val: u24) void {
            return std.mem.writeInt(u24, &me.arr[me.at][0..3], val, native_endian);
        }
    } {
        return .{ .arr = &self.idx_arr, .at = at * 3 };
    }

    /// Acquire a brand new node from the pool and init it with the required values
    pub fn acquire(pool: *Pool) !*@This() {
        const node = try pool.acquire();
        node.* = .{};
        return node;
    }

    /// Release the node to the pool; does Not release all the nodes; only this one
    pub fn releaseOne(self: *@This(), pool: *Pool) void {
        self.* = undefined;
        pool.release(self);
    }

    fn getNextNode(self: *@This(), path: []const u8) union(enum) { this: u8, next: u8, diff: u8 } {
        const maybe_consumed = mem.findDiff(u8, self.radix_str[0..self.radix_len], path[0 .. path.len - 1]);
        if (maybe_consumed == null) return .{ .idx = path[path.len - 1] };

        const consumed = maybe_consumed.?;
        if (consumed == self.radix_len) return .{ .next = path[self.radix_len] };
        return .{ .diff = consumed };
    }
};

const OpAdd = struct {
    /// The current edge we are on
    parent: *Node,
    /// The index of the current node inside of the parent
    idx_in_parent: u8,

    /// offset in mem
    offset: u34,

    /// The path that is left
    path: []const u8,
    /// The data we wanna add at the given path
    data: Mode,
    /// The allocator used to allocate and free nodes
    gpa: *Pool,

    fn executeNull(self: *const OpAdd) !void {
        std.debug.assert(self.cursed.isNull());

        var cursed = self.cursed;
        var idx = self.idx;
        var remaining = self.path;
        var parent = cursed.getParent(idx);

        while (true) {
            const node = try Node.init(self.gpa);
            const chunk_len = @min(remaining.len, node.radix_str.len);
            cursed.* = @bitCast(node);
            cursed._radix_len = @intCast(chunk_len);
            @memcpy(node.radix_str[0..chunk_len], remaining[0..chunk_len]);

            parent.children[idx] = cursed.*;

            if (chunk_len == remaining.len) {
                parent.count_minus_1[idx] = 0;
                parent.data[idx] = self.data;
                return;
            }

            parent.count_minus_1[idx] = 0;
            parent.data[idx] = .midway;

            remaining = remaining[chunk_len..];
            idx = remaining[0];
            remaining = remaining[1..];
            cursed = &node.children[idx];
            parent = node;
        }
    }

    /// idx is our index in the parent's block
    pub fn execute(self: *@This()) !void {
        if (self.cursed.isNull()) return self.executeNull();

        // At this point, it is guaranteed that there has not been any modification to the trie.
        // Yes, this is true even when we enter this after recursion.
        blk: switch (self.cursed.getNextNode(self.idx)) {
            .this => self.cursed.getParent(self.idx).data[self.idx] = self.data,
            .node => |next| {
                self.idx = next;
                self.path = self.path[@as(usize, self.cursed._radix_len) + 1 ..];
                self.cursed = &self.cursed.ptr().?.children[next];

                if (self.cursed.isNull()) executeNull(self) catch |e| {
                    self.freeChain();
                    self.cursed.* = .{};
                    return e;
                } else {
                    // This function is just a glorified for loop; the behavior is same as
                    // return @call(.always_tail, execute, .{self});
                    continue :blk self.cursed.getNextNode(self.idx);
                }
            },
            .consumed => |consumed| {
                const parent = self.cursed.getParent(self.idx);
                var old = self.cursed.*;
                const old_node = old.ptr().?;
                std.debug.assert(consumed < old._radix_len);
                const olds_new_idx = old_node.radix_str[consumed];

                const node = try Node.init(self.gpa); // No change was made so no harm
                node.count_minus_1[olds_new_idx] = parent.count_minus_1[self.idx];
                node.data[olds_new_idx] = parent.data[self.idx];
                @memcpy(node.radix_str[0..consumed], old_node.radix_str[0..consumed]);

                self.cursed.* = @bitCast(node);
                std.debug.assert(self.cursed._radix_len == 0);
                self.cursed._radix_len = consumed;

                if (self.path.len == consumed) {
                    parent.count_minus_1[self.idx] = 0;
                    parent.data[self.idx] = self.data;
                } else {
                    std.debug.assert(self.path.len > consumed);

                    const new_idx = self.path[consumed];
                    executeNull(.{
                        .idx = new_idx,
                        .cursed = &node.children[new_idx],
                        .path = self.path[@as(usize, consumed) + 1 ..],
                        .data = self.data,
                        .gpa = self.gpa,
                    }) catch |e| {
                        self.freeChain();
                        self.cursed.* = old;
                        return e;
                    };

                    parent.count_minus_1[self.idx] = 1;
                    parent.data[self.idx] = .midway;
                }

                const olds_new_str = old_node.radix_str[@as(usize, consumed) + 1 .. old._radix_len];
                std.mem.copyForwards(I, old_node.radix_str[0..olds_new_str.len], olds_new_str);
                old._radix_len = @intCast(olds_new_str.len);
                node.children[olds_new_idx] = old;
            },
        }
    }

    // Separate free function that does not blow up the stack
    fn freeChain(self: *const @This()) void {
        var ptr = self.cursed.ptr() orelse return;
        while (true) {
            const next = ptr.children[
                ptr.firstChild() orelse {
                    self.gpa.destroy(ptr);
                    return;
                }
            ];
            self.gpa.destroy(ptr);
            ptr = next;
        }
    }
};

const Mode = packed struct(u8) {
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
