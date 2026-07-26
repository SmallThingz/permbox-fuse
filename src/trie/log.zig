const std = @import("std");
const root = @import("root");
const logging_options = @import("logging_options");
const my_name = logging_options.module_name;
const logger = if (@hasDecl(root, "getLogger")) root.getLogger(my_name) else struct {};

/// You should use this if any of the args has a side-effect
pub const enabled = @hasDecl(logger, "log");
pub const log = if (enabled) logger.log else void;

pub fn err(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
    @branchHint(.cold);
    if (enabled) log(src, .err, format, args);
}

/// Log a warning message. This log level is intended to be used if
/// it is uncertain whether something has gone wrong or not, but the
/// circumstances would be worth investigating.
pub fn warn(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
    @branchHint(.unlikely);
    if (enabled) log(src, .warn, format, args);
}

/// Log an info message. This log level is intended to be used for
/// general messages about the state of the program.
pub fn info(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
    if (enabled) log(src, .info, format, args);
}

/// Log a debug message. This log level is intended to be used for
/// messages which are only useful for debugging.
pub fn debug(comptime src: std.builtin.SourceLocation, comptime format: []const u8, args: anytype) void {
    if (enabled) log(src, .debug, format, args);
}
