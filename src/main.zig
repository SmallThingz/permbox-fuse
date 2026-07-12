const std = @import("std");
const permtrie = @import("permtrie");
const fuse = @import("fuse.zig");

pub fn main(minimal_init: std.process.Init.Minimal) noreturn {
    const ops, const log = blk: {
        var retval: fuse.c.struct_fuse_operations = .{};
        var log: []const u8 = "";
        inline for (@typeInfo(@TypeOf(retval)).@"struct".fields) |f| {
            const want_t = @typeInfo(@typeInfo(f.type).optional.child).pointer.child;
            if (@hasDecl(@This(), f.name)) {
                const have_t = @FieldType(@This(), f.name);
                if (have_t != want_t) {
                    log = log ++ std.fmt.comptimePrint("TYPE MISMATCH: {s}\n\twant:{s}\n\thave:{s}\n\n", .{ f.name, @typeName(want_t), @typeName(have_t) });
                } else {
                    @field(retval, f.name) = &@field(@This(), f.name);
                }
            } else {
                log = log ++ std.fmt.comptimePrint("ABSENT: {s}\n\ttype:{s}\n\n", .{ f.name, @typeName(want_t) });
            }
        }
        break :blk .{ retval, log };
    };

    fuse.c.fuse_log(fuse.c.FUSE_LOG_WARNING, "%s", log);

    std.c.exit(fuse.c.fuse_main(@intCast(minimal_init.args.vector.len), minimal_init.args.vector.ptr, ops));
}
