const std = @import("std");

const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("unistd.h");
});

pub const reset = "\x1b[0m";
pub const bold = "\x1b[1m";
pub const dim = "\x1b[2m";
pub const red = "\x1b[31m";
pub const green = "\x1b[32m";
pub const yellow = "\x1b[33m";
pub const blue = "\x1b[34m";
pub const magenta = "\x1b[35m";
pub const cyan = "\x1b[36m";
pub const bright_red = "\x1b[91m";
pub const bright_green = "\x1b[92m";
pub const bright_blue = "\x1b[94m";

var color_state: std.atomic.Value(u8) = .init(0);

pub fn colorsEnabled() bool {
    const cached = color_state.load(.acquire);
    if (cached != 0) return cached == 2;
    const enabled = c.isatty(c.STDERR_FILENO) == 1 and c.getenv("NO_COLOR") == null;
    color_state.store(if (enabled) 2 else 1, .release);
    return enabled;
}

pub fn log(
    comptime module_name: []const u8,
    comptime src: std.builtin.SourceLocation,
    comptime level: std.log.Level,
    comptime format: []const u8,
    args: anytype,
) void {
    if (colorsEnabled()) {
        std.debug.print(
            levelColor(level) ++ bold ++ levelLabel(level) ++ reset ++
                dim ++ " [" ++ module_name ++ "] {s}:{d}:{d} {s}" ++ reset ++
                "  " ++ format ++ "\n",
            .{ src.file, src.line, src.column, src.fn_name } ++ args,
        );
    } else {
        std.debug.print(
            levelLabel(level) ++ " [" ++ module_name ++ "] {s}:{d}:{d} {s}  " ++
                format ++ "\n",
            .{ src.file, src.line, src.column, src.fn_name } ++ args,
        );
    }
}

pub fn label(comptime color: []const u8, comptime text: []const u8) void {
    if (colorsEnabled())
        std.debug.print(color ++ bold ++ text ++ reset, .{})
    else
        std.debug.print(text, .{});
}

fn levelColor(comptime level: std.log.Level) []const u8 {
    return switch (level) {
        .err => bright_red,
        .warn => yellow,
        .info => bright_blue,
        .debug => magenta,
    };
}

fn levelLabel(comptime level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "ERROR",
        .warn => "WARN ",
        .info => "INFO ",
        .debug => "DEBUG",
    };
}
