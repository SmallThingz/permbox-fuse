//! libfuse bindings shared by the low-level daemon.
const std = @import("std");

pub const api_version = 318;

pub const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cDefine("FUSE_USE_VERSION", std.fmt.comptimePrint("{d}", .{api_version}));
    @cInclude("fuse_lowlevel.h");
    @cInclude("fuse_log.h");
    @cInclude("dirent.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
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
    reserved: [2]u64,

    comptime {
        std.debug.assert(@sizeOf(@This()) == @sizeOf(c.struct_fuse_file_info));
    }
};

/// Helpers for `struct fuse_file_info` fields that are bitfields or need casts.
pub const FileInfo = struct {
    pub fn flags(fi: *const c.struct_fuse_file_info) i32 {
        return @as(*const align(1) FuseFileInfo, @ptrCast(fi)).flags;
    }
    pub fn fh(fi: *const c.struct_fuse_file_info) u64 {
        return @as(*const align(1) FuseFileInfo, @ptrCast(fi)).fh;
    }
    pub fn setFh(fi: *c.struct_fuse_file_info, val: u64) void {
        @as(*align(1) FuseFileInfo, @ptrCast(fi)).fh = val;
    }
    pub fn backingId(fi: *const c.struct_fuse_file_info) i32 {
        return @as(*const align(1) FuseFileInfo, @ptrCast(fi)).backing_id;
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
