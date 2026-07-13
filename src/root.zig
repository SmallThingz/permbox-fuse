//! This has the implementation of the trie that tracks the permissions
const std = @import("std");
const builtin = @import("builtin");
const mem = @import("mem.zig");

const children_count = 1 << 8;
const I = u8;
/// The total size of the node will be 2^8 * (2^2 | 2^3)
/// Adding the data block makes this  2^8 * (2 + 2^2 | 2 + 2^3) = 1.50 KiB | 2.50KiB
/// for smp allocatore
///     for 32 bit closest size class higher than 1.25 KiB is 2KiB; got 0.5KiB = 2^8 * 3
///     for 64 bit closest size class higher than 2.25 KiB is 4KiB; got 1.5KiB = 2^8 * 7
const node_size: struct { total: usize, free: usize } = switch (@bitSizeOf(usize)) {
    32 => @compileError("TODO: add 32 bit support"),
    // 32 => .{ .total = 1 << 11, .free = (1 << 8) * 3 },
    64 => .{ .total = 1 << 12, .free = (1 << 8) * 7 },
    else => |v| @compileError(std.fmt.comptimePrint("unsupported register width of {d}", .{v})),
};

const nodepopcnt = @popCount(node_size.total / 2);
const RadixInt = @Int(.unsigned, nodepopcnt);

const Node = struct {
    /// Set the alignment
    _: void align(node_size.total / 2),
    /// Childrens, if they exist
    ///
    /// Note that it might seem inticing to place the allocation inline along with one data pointer with
    /// [options.children_count]?*@This() & ?*options.data but that is actually a prettie bad idea.
    ///
    /// Most modern allocators use size classes; since usize is a multiple of 2,
    /// total size of this block is gonna be same as size class.
    /// But note that the data pointer must also takes 1 usize; that increases our size class of node allocation and wastes a LOT of space.
    /// for 64wide register and children_count = 256; that would likely waste ~1KiB atleast if not more
    children: [children_count]Cursed = children_count ** [1]Cursed{},
    /// The count for the childrens
    count_minus_1: [children_count]I = undefined,
    /// If this is non-null; this node has data
    data: [children_count]Mode = children_count ** [1]Mode.midway,

    /// This would have been wasted anyways
    radix_str: [@divExact(node_size.free, @sizeOf(I))]I = undefined,

    comptime {
        std.debug.assert(@alignOf(@This()) >= children_count);
        std.debug.assert(@sizeOf(@This()) == node_size.total);
    }

    pub fn init(gpa: std.mem.Allocator) !*@This() {
        const node = try gpa.create(@This());
        node.* = .{};
        return node;
    }

    pub fn deinit(self: *@This(), gpa: std.mem.Allocator) void {
        gpa.destroy(self);
    }
};

/// Use alignment hacks to store lengths
pub const Cursed = packed struct(usize) {
    /// The upper part of the pointer; this being 0 means the node is null.
    _upper: @Int(.unsigned, @bitSizeOf(usize) - nodepopcnt) = 0,
    /// Zero length means this is the terminal node; we are setting the upper part anyways so no harm in setting this too.
    _radix_len: RadixInt = 0,

    pub inline fn isNull(self: *const @This()) bool {
        // The lower part must be 0 if the upper is 0
        return @as(usize, @bitCast(self.underlying)) == 0;
    }

    pub inline fn ptr(self: *const @This()) ?*Node {
        return @bitCast(Cursed{ ._upper = self._upper });
    }

    fn getNextNode(self: *@This(), path: [:0]const I) union(enum) { this, node: I, consumed: RadixInt } {
        const node = self.ptr().?;
        const maybe_consumed = mem.findDiff(I, node.radix_str[0..self._radix_len], path);
        if (maybe_consumed) |consumed| {
            if (consumed == self._radix_len) return .{ .node = path[consumed] };
            return .{ .consumed = consumed };
        } else {
            return .this;
        }
    }

    fn getParent(self: *@This(), self_idx: I) *Node {
        const field = "children";
        const start = (@as([*]@This(), @ptrCast(self)) - self_idx);
        return @fieldParentPtr(field, @as(@FieldType(Node, field), @ptrCast(start)));
    }
};

const OpAdd = struct {
    cursed: *Cursed,
    path: []const u8,
    data: Mode,
    idx: u8,
    gpa: std.mem.Allocator,

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
        // At this point, it is guaranteed that there has not been any modification to the trie.
        // Yes, this is true even when we enter this after recursion.
        blk: switch (self.cursed.getNextNode(self.idx)) {
            .this => self.cursed.getParent(self.idx).data[self.idx] = self.data,
            .node => |next| {
                self.cursed = &self.cursed.ptr().?.children[next];
                self.idx = next;
                self.path = self.path[@as(usize, self.cursed._radix_len) + 1 ..];

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
            const next = blk: for (ptr.children) |c| {
                if (!c.isNull()) {
                    @branchHint(.unlikely);
                    break :blk c.ptr();
                }
            } else {
                self.gpa.destroy(ptr);
                return;
            };

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
