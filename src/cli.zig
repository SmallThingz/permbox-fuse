const std = @import("std");
const permfuse = @import("permfuse");
const terminal = @import("terminal.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub fn getLogger(comptime module_name: []const u8) type {
    return struct {
        pub fn log(
            comptime src: std.builtin.SourceLocation,
            comptime level: std.log.Level,
            comptime format: []const u8,
            args: anytype,
        ) void {
            terminal.log(module_name, src, level, format, args);
        }
    };
}

const MountContext = struct {
    driver: *permfuse.Driver,
    mountpoint: [:0]const u8,
    io_uring: bool,
    arguments: []const [:0]const u8,
    finished: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),

    fn run(self: *MountContext) void {
        self.driver.mount(std.heap.c_allocator, self.mountpoint, .{
            .io_uring = self.io_uring,
            .arguments = self.arguments,
        }) catch |err| {
            terminal.label(terminal.bright_red, "mount failed: ");
            std.debug.print("{t}\n", .{err});
            self.failed.store(true, .release);
        };
        self.finished.store(true, .release);
    }
};

pub fn main(init: std.process.Init) !u8 {
    const raw_args = init.minimal.args.vector;
    const args = try init.gpa.alloc([:0]const u8, raw_args.len);
    defer init.gpa.free(args);
    for (raw_args, args) |arg, *parsed| parsed.* = std.mem.span(arg);

    var config = permfuse.options.parse(args) catch |err| {
        printUsage(err);
        return 2;
    };
    defer config.deinit();

    std.Io.Dir.cwd().createDirPath(init.io, config.mountpoint) catch |err| {
        terminal.label(terminal.bright_red, "error: ");
        std.debug.print("cannot create mountpoint {s}: {t}\n", .{ config.mountpoint, err });
        return 1;
    };

    var driver: permfuse.Driver = undefined;
    driver.init(init.io, .{
        .backing_path = config.backing,
        .policy_path = config.policy,
        .state_path = config.state,
        .passthrough = config.passthrough,
    }) catch |err| {
        terminal.label(terminal.bright_red, "initialization failed: ");
        std.debug.print("{t}\n", .{err});
        return 1;
    };
    defer driver.deinit();

    var extra: std.ArrayList([:0]const u8) = .empty;
    defer extra.deinit(init.gpa);
    for (config.fuse_args[3..]) |arg| {
        if (!std.mem.eql(u8, arg, config.mountpoint))
            try extra.append(init.gpa, arg);
    }

    var mount_context = MountContext{
        .driver = &driver,
        .mountpoint = config.mountpoint,
        .io_uring = config.io_uring,
        .arguments = extra.items,
    };
    var mount_thread = try std.Thread.spawn(.{}, MountContext.run, .{&mount_context});
    var joined = false;
    defer if (!joined) {
        driver.requestUnmount();
        mount_thread.join();
    };

    terminal.label(terminal.bright_green, "mounted configuration\n");
    std.debug.print("  backing    {s}\n  mountpoint {s}\n", .{ config.backing, config.mountpoint });
    terminal.label(terminal.dim, "  type 'help' for live policy commands\n");

    var line_ptr: [*c]u8 = null;
    var line_capacity: usize = 0;
    defer c.free(line_ptr);
    while (true) {
        if (mount_context.finished.load(.acquire) and !joined) {
            mount_thread.join();
            joined = true;
            terminal.label(terminal.yellow, "mount loop stopped\n");
        }
        terminal.label(terminal.cyan, "permfuse");
        terminal.label(terminal.dim, " > ");
        const length = c.getline(&line_ptr, &line_capacity, c.stdin);
        if (length < 0) break;
        const line = std.mem.trim(u8, line_ptr[0..@intCast(length)], " \t\r\n");
        if (line.len == 0) continue;
        const keep_running = executeCommand(init, &driver, line, joined) catch |err| {
            terminal.label(terminal.bright_red, "error: ");
            std.debug.print("{t}\n", .{err});
            continue;
        };
        if (!keep_running) break;
        if (std.mem.eql(u8, firstWord(line), "unmount") and !joined) {
            mount_thread.join();
            joined = true;
        }
    }

    if (!joined) {
        driver.requestUnmount();
        mount_thread.join();
        joined = true;
    }
    return if (mount_context.failed.load(.acquire)) 1 else 0;
}

fn executeCommand(
    init: std.process.Init,
    driver: *permfuse.Driver,
    line: []const u8,
    unmounted: bool,
) !bool {
    var words = std.mem.tokenizeAny(u8, line, " \t");
    const command = words.next().?;

    if (std.mem.eql(u8, command, "help")) {
        printHelp();
    } else if (std.mem.eql(u8, command, "show")) {
        const text = try driver.policyToText(init.gpa);
        defer init.gpa.free(text);
        std.debug.print("{s}", .{text});
    } else if (std.mem.eql(u8, command, "get")) {
        const path = words.next() orelse return error.MissingPath;
        const exact = try driver.getRule(path);
        const effective = try driver.evaluate(path);
        std.debug.print("exact: ", .{});
        printMode(exact);
        std.debug.print("effective: ", .{});
        printMode(effective);
    } else if (std.mem.eql(u8, command, "set")) {
        const path = words.next() orelse return error.MissingPath;
        const flags_start = skipWords(line, 2) orelse return error.MissingFlags;
        const mode = try permfuse.parseModeText(flags_start);
        try driver.setRule(path, mode);
        terminal.label(terminal.bright_green, "updated  ");
        std.debug.print("{s}\n", .{path});
    } else if (std.mem.eql(u8, command, "del")) {
        const path = words.next() orelse return error.MissingPath;
        _ = try driver.removeRule(path);
        terminal.label(terminal.yellow, "removed  ");
        std.debug.print("{s}\n", .{path});
    } else if (std.mem.eql(u8, command, "load")) {
        const path = words.next() orelse return error.MissingFile;
        const text = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(16 * 1024 * 1024));
        defer init.gpa.free(text);
        try driver.replacePolicyFromText(init.gpa, text);
        terminal.label(terminal.bright_green, "loaded   ");
        std.debug.print("{s}\n", .{path});
    } else if (std.mem.eql(u8, command, "save")) {
        const path = words.next() orelse return error.MissingFile;
        const text = try driver.policyToText(init.gpa);
        defer init.gpa.free(text);
        try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = text });
        terminal.label(terminal.bright_green, "saved    ");
        std.debug.print("{s}\n", .{path});
    } else if (std.mem.eql(u8, command, "unmount")) {
        driver.requestUnmount();
    } else if (std.mem.eql(u8, command, "apply")) {
        if (!unmounted) return error.StillMounted;
        const limit = if (words.next()) |value|
            try std.fmt.parseInt(usize, value, 10)
        else
            null;
        const remove = if (words.next()) |value| std.mem.eql(u8, value, "remove") else false;
        const result = try driver.applyOverlay(init.gpa, .{
            .max_files = limit,
            .remove_applied = remove,
        });
        terminal.label(terminal.bright_green, "overlay  ");
        std.debug.print("applied={}, skipped={}, remaining={}\n", .{
            result.applied,
            result.skipped,
            result.remaining,
        });
    } else if (std.mem.eql(u8, command, "quit") or std.mem.eql(u8, command, "exit")) {
        if (!unmounted) driver.requestUnmount();
        return false;
    } else {
        return error.UnknownCommand;
    }
    return true;
}

fn firstWord(line: []const u8) []const u8 {
    return line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
}

fn skipWords(line: []const u8, count: usize) ?[]const u8 {
    var index: usize = 0;
    for (0..count) |_| {
        while (index < line.len and (line[index] == ' ' or line[index] == '\t')) index += 1;
        if (index == line.len) return null;
        while (index < line.len and line[index] != ' ' and line[index] != '\t') index += 1;
    }
    while (index < line.len and (line[index] == ' ' or line[index] == '\t')) index += 1;
    return if (index == line.len) null else line[index..];
}

fn printMode(mode: ?permfuse.Mode) void {
    if (mode) |value| {
        std.debug.print("kind={t}, read={t}, write={t}, execute={t}\n", .{
            value.k,
            value.r,
            value.w,
            value.x,
        });
    } else {
        std.debug.print("<none>\n", .{});
    }
}

fn printHelp() void {
    terminal.label(terminal.bright_blue, "Policy\n");
    std.debug.print(
        "  show                         print the complete fs block\n" ++
            "  get PATH                     show exact and effective rules\n" ++
            "  set PATH FLAGS               insert or replace a live rule\n" ++
            "  del PATH                     remove an explicit rule\n" ++
            "  load FILE                    replace policy from an fs block\n" ++
            "  save FILE                    save policy as an fs block\n",
        .{},
    );
    terminal.label(terminal.bright_blue, "Mount and overlay\n");
    std.debug.print(
        "  unmount                      stop the active mount\n" ++
            "  apply [MAX_FILES] [remove]   apply overlay data after unmount\n" ++
            "  quit                         unmount and exit\n",
        .{},
    );
}

fn printUsage(err: anyerror) void {
    terminal.label(terminal.bright_red, "error: ");
    std.debug.print(
        "{t}\n",
        .{err},
    );
    terminal.label(terminal.bright_blue, "usage\n  ");
    std.debug.print(
        "permfuse --backing=/absolute/root --policy=/absolute/trie " ++
            "[--state=/absolute/session] [--no-io-uring] [--no-passthrough] " ++
            "/absolute/mountpoint [FUSE options]\n",
        .{},
    );
}
