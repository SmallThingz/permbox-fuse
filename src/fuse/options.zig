const std = @import("std");

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    lower: [:0]const u8,
    policy: [:0]const u8,
    session: [:0]const u8,
    mountpoint: [:0]const u8,
    fuse_args: []const [:0]const u8,
    io_uring: bool,
    passthrough: bool,

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
    }
};

pub const ParseError = error{
    OutOfMemory,
    MissingLower,
    MissingPolicy,
    MissingSession,
    MissingMountpoint,
    LowerNotAbsolute,
    PolicyNotAbsolute,
    SessionNotAbsolute,
    MountpointNotAbsolute,
    PathOverlap,
};

pub fn parse(argv: []const [:0]const u8) ParseError!Config {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var lower: ?[]const u8 = null;
    var policy: ?[]const u8 = null;
    var session: ?[]const u8 = null;
    var mountpoint: ?[]const u8 = null;
    var io_uring = true;
    var passthrough = true;
    var remaining: std.ArrayList([]const u8) = .empty;
    var after_dash = false;

    for (argv[1..]) |argument| {
        if (!after_dash and std.mem.eql(u8, argument, "--")) {
            after_dash = true;
        } else if (!after_dash and std.mem.startsWith(u8, argument, "--lower=")) {
            lower = argument["--lower=".len..];
        } else if (!after_dash and std.mem.startsWith(u8, argument, "--policy=")) {
            policy = argument["--policy=".len..];
        } else if (!after_dash and std.mem.startsWith(u8, argument, "--session=")) {
            session = argument["--session=".len..];
        } else if (!after_dash and std.mem.eql(u8, argument, "--no-io-uring")) {
            io_uring = false;
        } else if (!after_dash and std.mem.eql(u8, argument, "--no-passthrough")) {
            passthrough = false;
        } else {
            if (argument.len != 0 and argument[0] != '-' and mountpoint == null)
                mountpoint = argument;
            try remaining.append(allocator, argument);
        }
    }

    const lower_raw = lower orelse return error.MissingLower;
    const policy_raw = policy orelse return error.MissingPolicy;
    const session_raw = session orelse return error.MissingSession;
    const mount_raw = mountpoint orelse return error.MissingMountpoint;
    if (!std.fs.path.isAbsolute(lower_raw)) return error.LowerNotAbsolute;
    if (!std.fs.path.isAbsolute(policy_raw)) return error.PolicyNotAbsolute;
    if (!std.fs.path.isAbsolute(session_raw)) return error.SessionNotAbsolute;
    if (!std.fs.path.isAbsolute(mount_raw)) return error.MountpointNotAbsolute;

    const normalized_lower = try resolve(allocator, lower_raw);
    const normalized_session = try resolve(allocator, session_raw);
    const normalized_mount = try resolve(allocator, mount_raw);
    // A lower path of "/" necessarily contains every path lexically. Actual
    // mount topology, including separate filesystems below "/", cannot be
    // validated from strings. Only prevent the session from containing the
    // public mount or vice versa.
    if (overlap(normalized_session, normalized_mount))
        return error.PathOverlap;

    var fuse_args: std.ArrayList([:0]const u8) = .empty;
    try fuse_args.append(allocator, try allocator.dupeZ(u8, argv[0]));
    try fuse_args.append(allocator, try allocator.dupeZ(u8, "-o"));
    try fuse_args.append(allocator, try allocator.dupeZ(
        u8,
        if (io_uring) "io_uring,default_permissions" else "default_permissions",
    ));
    for (remaining.items) |argument|
        try fuse_args.append(allocator, try allocator.dupeZ(u8, argument));

    return .{
        .arena = arena,
        .lower = try allocator.dupeZ(u8, normalized_lower),
        .policy = try allocator.dupeZ(u8, policy_raw),
        .session = try allocator.dupeZ(u8, normalized_session),
        .mountpoint = try allocator.dupeZ(u8, normalized_mount),
        .fuse_args = try fuse_args.toOwnedSlice(allocator),
        .io_uring = io_uring,
        .passthrough = passthrough,
    };
}

fn resolve(allocator: std.mem.Allocator, path: []const u8) ParseError![]u8 {
    return std.fs.path.resolve(allocator, &.{path}) catch error.OutOfMemory;
}

fn contains(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, child)) return true;
    if (parent.len == 1 and parent[0] == '/') return true;
    return child.len > parent.len and std.mem.startsWith(u8, child, parent) and
        child[parent.len] == '/';
}

fn overlap(a: []const u8, b: []const u8) bool {
    return contains(a, b) or contains(b, a);
}

test "parse accepts root lower and keeps session disjoint from mount" {
    const args = [_][:0]const u8{
        "permfs",
        "--lower=/",
        "--policy=/policy",
        "--session=/state",
        "/mount",
    };
    var config = try parse(&args);
    defer config.deinit();
    try std.testing.expectEqualStrings("/", config.lower);
    try std.testing.expectEqualStrings("/state", config.session);
    try std.testing.expect(config.io_uring);
    try std.testing.expect(config.passthrough);

    const bad = [_][:0]const u8{
        "permfs",
        "--lower=/",
        "--policy=/policy",
        "--session=/mount/session",
        "/mount",
    };
    try std.testing.expectError(error.PathOverlap, parse(&bad));
}

test "parse rejects missing required paths" {
    const args = [_][:0]const u8{ "permfs", "--lower=/lower", "/mount" };
    try std.testing.expectError(error.MissingPolicy, parse(&args));
}
