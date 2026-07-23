//! libfuse bindings shared by the low-level daemon.
const std = @import("std");

pub const api_version = 318;

pub const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cDefine("FUSE_USE_VERSION", std.fmt.comptimePrint("{d}", .{api_version}));
    @cInclude("fuse_shim.h");
    @cInclude("fuse_log.h");
    @cInclude("dirent.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("unistd.h");
});
