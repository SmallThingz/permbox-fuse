//! This has the implementation of the trie that tracks the permissions
const std = @import("std");

const children_count = 1 << 8;
const I = u8;
/// The total size of the node will be 2^8 * (2^2 | 2^3)
/// Adding the data block makes this  2^8 * (1 + 2^2 | 1 + 2^3) = 1.25 KiB | 2.25KiB
/// for smp allocatore
///     for 32 bit closest size class higher than 1.25 KiB is 2KiB; got 0.75KiB = 2^8 * 3
///     for 64 bit closest size class higher than 2.25 KiB is 4KiB; got 1.75KiB = 2^8 * 7
const node_size: struct { total: usize, free: usize } = switch (@bitSizeOf(usize)) {
    32 => .{ .total = 1 << 11, .free = (1 << 8) * 3 },
    64 => .{ .total = 1 << 12, .free = (1 << 8) * 7 },
    else => |v| @compileError(std.fmt.comptimePrint("unsupported register width of {d}", .{v})),
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
        /// This is a mid-way node and does not have it's own data.
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

const Node = struct {
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
    /// If this is non-null; this node has data
    data: [children_count]Mode = children_count ** [1]Mode.midway,
    /// This would have been wasted anyways
    free: Free = .{},

    comptime {
        std.debug.assert(@alignOf(@This()) >= children_count);
        std.debug.assert(@sizeOf(@This()) == node_size.total);
    }

    /// Use alignment hacks to help store lengths
    pub const Cursed = packed struct(usize) {
        upper: @Int(.unsigned, @bitSizeOf(usize) - 8) = 0,
        count_minus_1: u8 = 0,

        pub fn ptr(self: @This()) ?*Node {
            var copy = self;
            copy.count_minus_1 = 0;
            return @bitCast(copy);
        }
    };

    pub const Free = struct {
        radix_len: u16 = 0,
        data: [@divExact(node_size.free - 2, @sizeOf(I))]I = undefined,

        comptime {
            std.debug.assert(@sizeOf(@This()) == node_size.free);
        }
    };

    pub fn init(gpa: std.mem.Allocator) !*@This() {
        const node = try gpa.create(@This());
        node.* = .{};
        return node;
    }
};

const Slab = struct {
    children: [256]Node,
};
