const std = @import("std");
const testing = std.testing;

/// Parsed configuration for the permbox-fuse daemon.
///
/// All string memory is owned by the internal arena; call `deinit()` to
/// release everything at once.
pub const Config = struct {
    arena: std.heap.ArenaAllocator,

    /// Absolute path to the backing store file.
    backing: [:0]const u8,
    /// Absolute path to the permission policy file.
    policy: [:0]const u8,
    /// Optional directory for sparse overlay files.
    state: ?[:0]const u8,
    /// Absolute mountpoint path (extracted from the first positional argument).
    mountpoint: [:0]const u8,
    /// Null-terminated arguments ready for libfuse, including argv[0].
    ///
    /// Each string is either a reference into the original `argv` or arena-
    /// owned memory.  All are valid for the lifetime of this Config.
    fuse_args: []const [:0]const u8,

    /// Whether `io_uring` was enabled in the default options (true by
    /// default; `--no-io-uring` sets it false).
    io_uring: bool,
    /// Whether passthrough mode was requested (true by default;
    /// `--no-passthrough` sets it false).
    passthrough: bool,

    /// Free all arena memory.  Config must not be used after this call.
    pub fn deinit(self: *Config) void {
        self.arena.deinit();
    }
};

/// Set of errors that can occur during argument parsing.
pub const ParseError = error{
    OutOfMemory,
    MissingBacking,
    MissingPolicy,
    MissingMountpoint,
    BackingNotAbsolute,
    PolicyNotAbsolute,
    StateNotAbsolute,
    MountpointNotAbsolute,
    BackingAliasesMountpoint,
};

/// Parse command-line arguments into a `Config`.
///
/// `argv` should follow the standard convention where `argv[0]` is the
/// program name (it is skipped internally).
///
/// Recognised permbox-specific flags:
///   `--backing=PATH`         (required, absolute)
///   `--policy=PATH`          (required, absolute)
///   `--no-io-uring`          disable io_uring
///   `--no-passthrough`       disable passthrough
///
/// The first positional argument is interpreted as the mountpoint.
/// Everything after `--` is treated as a positional / FUSE argument.
///
/// Default FUSE options `-o default_permissions` (and
/// `io_uring` unless `--no-io-uring` was given) are prepended to
/// `fuse_args`.
pub fn parse(argv: []const [:0]const u8) ParseError!Config {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var backing: ?[]const u8 = null;
    var policy: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var mountpoint: ?[]const u8 = null;
    var io_uring = true;
    var passthrough = true;

    // Remaining arguments after extracting permbox-specific flags.
    var remaining = std.ArrayList([]const u8).empty;

    var i: usize = 1; // skip argv[0] (program name)
    var double_dash = false;

    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (double_dash) {
            try remaining.append(allocator, arg);
            continue;
        }

        if (std.mem.eql(u8, arg, "--")) {
            double_dash = true;
            continue;
        }

        if (std.mem.startsWith(u8, arg, "--backing=")) {
            const value = arg["--backing=".len..];
            if (value.len == 0) return error.MissingBacking;
            backing = value;
        } else if (std.mem.startsWith(u8, arg, "--policy=")) {
            const value = arg["--policy=".len..];
            if (value.len == 0) return error.MissingPolicy;
            policy = value;
        } else if (std.mem.startsWith(u8, arg, "--state=")) {
            const value = arg["--state=".len..];
            if (value.len == 0) return error.StateNotAbsolute;
            state = value;
        } else if (std.mem.eql(u8, arg, "--no-io-uring")) {
            io_uring = false;
        } else if (std.mem.eql(u8, arg, "--no-passthrough")) {
            passthrough = false;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            // All other dash-prefixed arguments are treated as FUSE flags.
            try remaining.append(allocator, arg);
        } else {
            // Positional argument – first one is the mountpoint.
            if (mountpoint == null) {
                mountpoint = arg;
            }
            try remaining.append(allocator, arg);
        }
    }

    const b = backing orelse return error.MissingBacking;
    const p = policy orelse return error.MissingPolicy;
    const m = mountpoint orelse return error.MissingMountpoint;

    // ---- path validation ----
    if (!std.fs.path.isAbsolute(b)) return error.BackingNotAbsolute;
    if (!std.fs.path.isAbsolute(p)) return error.PolicyNotAbsolute;
    if (state) |path| if (!std.fs.path.isAbsolute(path)) return error.StateNotAbsolute;
    if (!std.fs.path.isAbsolute(m)) return error.MountpointNotAbsolute;
    if (std.mem.eql(u8, b, m)) return error.BackingAliasesMountpoint;

    // ---- build default -o string ----
    var o_buf = std.ArrayList(u8).empty;
    if (io_uring) try o_buf.appendSlice(allocator, "io_uring,");
    try o_buf.appendSlice(allocator, "default_permissions");

    // ---- assemble fuse_args ──────────────────────────────────────
    // Layout:  [argv[0], "-o", "<defaults>", <remaining user args>]
    // The mountpoint is inside `remaining` as a positional argument.
    var fuse_list = std.ArrayList([:0]const u8).empty;
    try fuse_list.append(allocator, try allocator.dupeZ(u8, argv[0]));
    try fuse_list.append(allocator, try allocator.dupeZ(u8, "-o"));
    try fuse_list.append(allocator, try allocator.dupeZ(u8, try o_buf.toOwnedSlice(allocator)));
    for (remaining.items) |arg| {
        try fuse_list.append(allocator, try allocator.dupeZ(u8, arg));
    }

    return Config{
        .arena = arena,
        .backing = try allocator.dupeZ(u8, b),
        .policy = try allocator.dupeZ(u8, p),
        .state = if (state) |path| try allocator.dupeZ(u8, path) else null,
        .mountpoint = try allocator.dupeZ(u8, m),
        .fuse_args = try fuse_list.toOwnedSlice(allocator),
        .io_uring = io_uring,
        .passthrough = passthrough,
    };
}

// ─── Tests ─────────────────────────────────────────────────────────

test "basic parse" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/data/store",
        "--policy=/etc/permbox/policy",
        "/mnt/point",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expectEqualStrings("/data/store", cfg.backing);
    try testing.expectEqualStrings("/etc/permbox/policy", cfg.policy);
    try testing.expectEqualStrings("/mnt/point", cfg.mountpoint);
    try testing.expect(cfg.io_uring);
    try testing.expect(cfg.passthrough);
}

test "defaults are set" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(cfg.io_uring);
    try testing.expect(cfg.passthrough);
}

test "no-io-uring disables io_uring" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "--no-io-uring",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(!cfg.io_uring);
    try testing.expect(cfg.passthrough);
}

test "no-passthrough disables passthrough" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "--no-passthrough",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(cfg.io_uring);
    try testing.expect(!cfg.passthrough);
}

test "both --no-* flags" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "--no-io-uring",
        "--no-passthrough",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(!cfg.io_uring);
    try testing.expect(!cfg.passthrough);
}

test "missing backing" {
    const args = [_][:0]const u8{
        "prog",
        "--policy=/b",
        "/mnt",
    };
    try testing.expectError(error.MissingBacking, parse(&args));
}

test "missing policy" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "/mnt",
    };
    try testing.expectError(error.MissingPolicy, parse(&args));
}

test "missing mountpoint" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
    };
    try testing.expectError(error.MissingMountpoint, parse(&args));
}

test "empty backing value" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=",
        "--policy=/b",
        "/mnt",
    };
    try testing.expectError(error.MissingBacking, parse(&args));
}

test "empty policy value" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=",
        "/mnt",
    };
    try testing.expectError(error.MissingPolicy, parse(&args));
}

test "non-absolute backing" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=relative/path",
        "--policy=/b",
        "/mnt",
    };
    try testing.expectError(error.BackingNotAbsolute, parse(&args));
}

test "non-absolute policy" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=relative/path",
        "/mnt",
    };
    try testing.expectError(error.PolicyNotAbsolute, parse(&args));
}

test "non-absolute mountpoint" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "relative/mnt",
    };
    try testing.expectError(error.MountpointNotAbsolute, parse(&args));
}

test "backing aliases mountpoint" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/same/path",
        "--policy=/b",
        "/same/path",
    };
    try testing.expectError(error.BackingAliasesMountpoint, parse(&args));
}

test "fuse args pass through" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "/mnt",
        "-o",
        "ro,noexec",
        "-d",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    // fuse_args layout: [-o, "<defaults>", "/mnt", "-o", "ro,noexec", "-d"]
    try testing.expectEqual(@as(usize, 7), cfg.fuse_args.len);
    try testing.expectEqualStrings("prog", cfg.fuse_args[0]);
    try testing.expectEqualStrings("-o", cfg.fuse_args[1]);

    // Index 1 is the default -o value (contains default_permissions etc.)
    try testing.expect(std.mem.indexOf(u8, cfg.fuse_args[2], "default_permissions") != null);

    try testing.expectEqualStrings("/mnt", cfg.fuse_args[3]);
    try testing.expectEqualStrings("-o", cfg.fuse_args[4]);
    try testing.expectEqualStrings("ro,noexec", cfg.fuse_args[5]);
    try testing.expectEqualStrings("-d", cfg.fuse_args[6]);
}

test "double-dash stops flag parsing" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "/mnt",
        "--",
        "--no-io-uring",
        "--no-passthrough",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    // --no-* after -- should be treated as positional args, not flags
    try testing.expect(cfg.io_uring);
    try testing.expect(cfg.passthrough);

    // The -- itself is consumed but not added to fuse_args.
    // fuse_args: [-o, defaults, /mnt, --no-io-uring, --no-passthrough]
    try testing.expectEqual(@as(usize, 6), cfg.fuse_args.len);
    try testing.expectEqualStrings("-o", cfg.fuse_args[1]);
    try testing.expectEqualStrings("/mnt", cfg.fuse_args[3]);
    try testing.expectEqualStrings("--no-io-uring", cfg.fuse_args[4]);
    try testing.expectEqualStrings("--no-passthrough", cfg.fuse_args[5]);
}

test "default -o contains io_uring when enabled" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(std.mem.indexOf(u8, cfg.fuse_args[2], "io_uring") != null);
}

test "default -o omits io_uring when disabled" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "--no-io-uring",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expect(std.mem.indexOf(u8, cfg.fuse_args[2], "io_uring") == null);
    try testing.expect(std.mem.indexOf(u8, cfg.fuse_args[2], "default_permissions") != null);
}

test "multiple positional args" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "/mnt",
        "extra1",
        "extra2",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    // Only the first positional is the mountpoint.
    try testing.expectEqualStrings("/mnt", cfg.mountpoint);

    // All positionals end up in fuse_args.
    try testing.expectEqualStrings("/mnt", cfg.fuse_args[3]);
    try testing.expectEqualStrings("extra1", cfg.fuse_args[4]);
    try testing.expectEqualStrings("extra2", cfg.fuse_args[5]);
}

test "fuse flags before positionals" {
    const args = [_][:0]const u8{
        "prog",
        "--backing=/a",
        "--policy=/b",
        "-f",
        "-s",
        "/mnt",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expectEqualStrings("/mnt", cfg.mountpoint);
    try testing.expectEqualStrings("-f", cfg.fuse_args[3]);
    try testing.expectEqualStrings("-s", cfg.fuse_args[4]);
    try testing.expectEqualStrings("/mnt", cfg.fuse_args[5]);
}

test "flags can appear in any order" {
    const args = [_][:0]const u8{
        "prog",
        "--no-io-uring",
        "--backing=/a",
        "/mnt",
        "--policy=/b",
    };
    var cfg = try parse(&args);
    defer cfg.deinit();

    try testing.expectEqualStrings("/a", cfg.backing);
    try testing.expectEqualStrings("/b", cfg.policy);
    try testing.expectEqualStrings("/mnt", cfg.mountpoint);
    try testing.expect(!cfg.io_uring);
    try testing.expect(cfg.passthrough);
}
