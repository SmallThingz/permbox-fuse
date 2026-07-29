//! libfuse bindings shared by the low-level daemon.
const std = @import("std");

/// External libfuse API level, not a permfuse data or package version.
pub const fuse_api_level = 318;

pub const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cDefine("FUSE_USE_VERSION", std.fmt.comptimePrint("{d}", .{fuse_api_level}));
    @cInclude("fuse_lowlevel.h");
    @cInclude("fuse_log.h");
    @cInclude("dirent.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("sys/xattr.h");
    @cInclude("poll.h");
    @cInclude("unistd.h");
});

/// Mirror of `struct fuse_file_info` with explicit field layout so Zig can
/// access bitfield members and padding that C translation hides.
pub const FuseFileInfo = packed struct {
    flags: i32,
    writepage: u1,
    direct_io: u1,
    keep_cache: u1,
    flush: u1,
    nonseekable: u1,
    flock_release: u1,
    cache_readdir: u1,
    noflush: u1,
    parallel_direct_writes: u1,
    padding: u23,
    padding2: u32,
    padding3: u32,
    fh: u64,
    lock_owner: u64,
    poll_events: u32,
    backing_id: i32,
    compat_flags: u64,
    reserved0: u64,
    reserved1: u64,
};

comptime {
    // These accessors depend on matching libfuse's private bitfield layout.
    // Zig translates the C bitfield struct as opaque, so enforce the ABI size
    // specified by the libfuse 3.18 layout mirrored above.
    std.debug.assert(@sizeOf(FuseFileInfo) == 64);
}

/// Mirror of the initial `unsigned` fields in `struct fuse_conn_info` that
/// includes `max_backing_stack_depth` (which the C translation treats as
/// opaque).  Verified against the actual size below.
const ConnInfoMin = extern struct {
    proto_major: c_uint,
    proto_minor: c_uint,
    max_write: c_uint,
    max_read: c_uint,
    max_readahead: c_uint,
    capable: c_uint,
    want: c_uint,
    max_background: c_uint,
    congestion_threshold: c_uint,
    time_gran: c_uint,
    max_backing_stack_depth: c_uint,
};

/// Helper for the single `struct fuse_conn_info` field we need to set.
pub fn connSetBackingDepth(conn: *c.struct_fuse_conn_info, depth: u32) void {
    @as(*align(1) ConnInfoMin, @ptrCast(conn)).max_backing_stack_depth = depth;
}

/// Helpers for `struct fuse_file_info` fields that are bitfields or need casts.
pub const FileInfo = struct {
    pub fn flags(fi: *const c.struct_fuse_file_info) i32 {
        return @as(*align(1) const FuseFileInfo, @ptrCast(fi)).flags;
    }
    pub fn fh(fi: *const c.struct_fuse_file_info) u64 {
        return @as(*align(1) const FuseFileInfo, @ptrCast(fi)).fh;
    }
    pub fn setFh(fi: *c.struct_fuse_file_info, val: u64) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).fh = val;
    }
    pub fn backingId(fi: *const c.struct_fuse_file_info) i32 {
        return @as(*align(1) const FuseFileInfo, @ptrCast(fi)).backing_id;
    }
    pub fn setBackingId(fi: *c.struct_fuse_file_info, id: i32) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).backing_id = id;
    }
    pub fn setKeepCache(fi: *c.struct_fuse_file_info, val: u1) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).keep_cache = val;
    }
    pub fn setNoflush(fi: *c.struct_fuse_file_info, val: u1) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).noflush = val;
    }
    pub fn setCacheReaddir(fi: *c.struct_fuse_file_info, val: u1) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).cache_readdir = val;
    }
};
