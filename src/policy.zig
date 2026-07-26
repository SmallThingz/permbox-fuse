//! Allocation-free policy decision layer for FUSE operations.
//!
//! Evaluates trie-stored rules via longest-prefix matching over slash-separated,
//! normalized absolute paths. Every decision function is a thin wrapper around
//! `evaluate()` — no heap allocation on any code path.
//!
//! Passthrough eligibility: kernel may bypass FUSE only when the evaluated rule
//! is `visible_raw` with r/w/x all `.allow` and write is not overlay.
//!
//! Hot functions are kept small; inline on the accessor wrappers.
const std = @import("std");
const permtrie = @import("permtrie");

pub const Mode = permtrie.Mode;
pub const K = Mode.K;
pub const A = Mode.A;
pub const W = Mode.W;

// ── Public API ──────────────────────────────────────────────────────────────

/// Evaluate policy for a normalized absolute path via longest-prefix component
/// matching.  Walks from the full path upward, stripping one component at a
/// time, and returns the first non-midway rule found.  Returns `null` when no
/// rule exists at all (default: hidden / no-access).
///
/// The path is expected to be a normalised absolute FUSE path (e.g. `/a/b/c`).
/// Must not be empty.
pub fn evaluate(path: []const u8) !?Mode {
    return permtrie.getLongestPrefix(path);
}

/// Stores an explicit rule. Callers coordinating open-handle snapshots must
/// hold their policy write lock around this operation.
pub fn set(path: []const u8, mode: Mode) !void {
    try permtrie.add(path, mode);
}

/// Removes an explicit rule and returns it.
pub fn remove(path: []const u8) !Mode {
    return permtrie.del(path);
}

/// Returns only an explicit rule, without ancestor inheritance.
pub fn get(path: []const u8) !?Mode {
    return permtrie.get(path);
}

/// Path is visible in the namespace (raw or virtual).
pub inline fn isAccessible(path: []const u8) !bool {
    const mode = (try evaluate(path)) orelse return false;
    return mode.k == .visible_raw or mode.k == .visible_virtual;
}

/// Read is always allowed (deny/ask → false).
pub inline fn canRead(path: []const u8) !bool {
    const mode = (try evaluate(path)) orelse return false;
    return mode.r == .allow;
}

/// Write is allowed (always-allow-w or overlay-w).
pub inline fn canWrite(path: []const u8) !bool {
    const mode = (try evaluate(path)) orelse return false;
    return mode.w == .allow or mode.w == .overlay;
}

/// Execute is always allowed (deny/ask → false).
pub inline fn canExecute(path: []const u8) !bool {
    const mode = (try evaluate(path)) orelse return false;
    return mode.x == .allow;
}

/// Metadata is visible (same as accessibility for now).
pub inline fn showMetadata(path: []const u8) !bool {
    return isAccessible(path);
}

/// True iff the kernel can bypass FUSE and serve the path directly from the
/// host backing filesystem.  Requires: visible_raw, read=always-allow,
/// write=always-allow-to-backing, exec=always-allow (no overlay).
pub inline fn canPassthrough(path: []const u8) !bool {
    const mode = (try evaluate(path)) orelse return false;
    return canPassthroughMode(mode);
}

pub inline fn canPassthroughMode(mode: Mode) bool {
    return mode.k == .visible_raw and
        mode.r == .allow and
        mode.w == .allow and
        mode.x == .allow;
}

// ── Tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectModeEqual(expected: Mode, actual: Mode) !void {
    try testing.expectEqual(@as(u8, @bitCast(expected)), @as(u8, @bitCast(actual)));
}

/// Init a fresh pool+global before each test so other tests never see stale
/// trie state.  Only the first call creates a new memfd; subsequent calls
/// cheaply reset the existing pool to a clean state.
var g_pool_prepared = false;
fn preparePool() !void {
    if (!g_pool_prepared) {
        const fd = try std.posix.memfd_create("policy-test", 0);
        try permtrie.init(fd);
        g_pool_prepared = true;
    } else {
        permtrie.reset();
    }
}

// ── evaluate ────────────────────────────────────────────────────────────────

test "evaluate: exact match returns the stored Mode" {
    try preparePool();
    try permtrie.add("/foo", Mode.dir);
    const result = try evaluate("/foo");
    try testing.expect(result != null);
    try expectModeEqual(Mode.dir, result.?);
}

test "evaluate: nonexistent path returns null" {
    try preparePool();
    try testing.expectEqual(@as(?Mode, null), try evaluate("/nope"));
}

test "evaluate: empty path returns null" {
    try preparePool();
    try testing.expectEqual(@as(?Mode, null), try evaluate(""));
}

test "evaluate: root rule is found" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    const result = try evaluate("/");
    try testing.expect(result != null);
    try expectModeEqual(Mode.dir, result.?);
}

test "evaluate: root rule inherited by descendants" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    try expectModeEqual(Mode.dir, (try evaluate("/foo")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/foo/bar")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/foo/bar/baz")).?);
}

test "evaluate: child rule overrides parent" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    try permtrie.add("/foo", Mode.file); // read=deny
    try expectModeEqual(Mode.file, (try evaluate("/foo")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/bar")).?); // still inherits root
}

test "evaluate: child rule inherited by deeper paths" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    try permtrie.add("/foo", Mode.file);
    try expectModeEqual(Mode.file, (try evaluate("/foo/bar")).?);
    try expectModeEqual(Mode.file, (try evaluate("/foo/bar/baz")).?);
}

test "evaluate: longest prefix wins" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    try permtrie.add("/a", Mode.file);
    try permtrie.add("/a/b", Mode.dir);
    try expectModeEqual(Mode.dir, (try evaluate("/")).?);
    try expectModeEqual(Mode.file, (try evaluate("/a")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/a/b")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/a/b/c")).?);
    try expectModeEqual(Mode.file, (try evaluate("/a/x")).?);
}

test "evaluate: mid-level path without own rule inherits from nearest ancestor" {
    try preparePool();
    try permtrie.add("/home", Mode.dir);
    try permtrie.add("/home/user/docs", Mode.file);
    // /home/user has no rule, /home/user/docs has one → /home/user/docs
    try expectModeEqual(Mode.file, (try evaluate("/home/user/docs")).?);
    // /home/user inherits from /home
    try expectModeEqual(Mode.dir, (try evaluate("/home/user")).?);
    // /home/user/docs/file inherits from /home/user/docs
    try expectModeEqual(Mode.file, (try evaluate("/home/user/docs/file")).?);
}

test "evaluate: midway nodes are transparent" {
    try preparePool();
    // Insert a path that creates midway internal nodes (via split).
    try permtrie.add("/abc", Mode.dir);
    try permtrie.add("/abd", Mode.file);
    // "/a" does not exist as a rule — midway nodes (data=0) should be skipped.
    try testing.expectEqual(@as(?Mode, null), try evaluate("/a"));
    // But "/abc" and "/abd" resolve correctly.
    try expectModeEqual(Mode.dir, (try evaluate("/abc")).?);
    try expectModeEqual(Mode.file, (try evaluate("/abd")).?);
}

test "evaluate: triple-component path with mixed rules" {
    try preparePool();
    try permtrie.add("/a/b/c", Mode.dir);
    try permtrie.add("/a", Mode.file);
    try expectModeEqual(Mode.file, (try evaluate("/a")).?);
    try expectModeEqual(Mode.file, (try evaluate("/a/x")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/a/b/c")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/a/b/c/d")).?);
}

// ── isAccessible ────────────────────────────────────────────────────────────

test "isAccessible: hidden when no rule" {
    try preparePool();
    try testing.expectEqual(false, try isAccessible("/hidden"));
}

test "isAccessible: visible_raw is accessible" {
    try preparePool();
    // Mode.dir has k=visible_raw
    try permtrie.add("/vis", Mode.dir);
    try testing.expect(try isAccessible("/vis"));
}

test "isAccessible: visible_virtual is accessible" {
    try preparePool();
    try permtrie.add("/virt", Mode{ .k = .visible_virtual, .r = .allow, .w = .overlay, .x = .allow });
    try testing.expect(try isAccessible("/virt"));
}

test "isAccessible: invisible is not accessible" {
    try preparePool();
    try permtrie.add("/hid", Mode{ .k = .invisible, .r = .deny, .w = .deny, .x = .deny });
    try testing.expectEqual(false, try isAccessible("/hid"));
}

test "isAccessible: child of invisible is also inaccessible" {
    try preparePool();
    try permtrie.add("/hid", Mode{ .k = .invisible, .r = .deny, .w = .deny, .x = .deny });
    try testing.expectEqual(false, try isAccessible("/hid/child"));
}

// ── canRead ─────────────────────────────────────────────────────────────────

test "canRead: deny returns false" {
    try preparePool();
    try permtrie.add("/f", Mode.file); // file has r=deny
    try testing.expectEqual(false, try canRead("/f"));
}

test "canRead: allow returns true" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .overlay, .x = .allow });
    try testing.expect(try canRead("/f"));
}

test "canRead: ask returns false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .ask, .w = .overlay, .x = .allow });
    try testing.expectEqual(false, try canRead("/f"));
}

test "canRead: no rule returns false" {
    try preparePool();
    try testing.expectEqual(false, try canRead("/nope"));
}

// ── canWrite ────────────────────────────────────────────────────────────────

test "canWrite: deny returns false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .deny, .w = .deny, .x = .allow });
    try testing.expectEqual(false, try canWrite("/f"));
}

test "canWrite: allow (always-allow-w) returns true" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow });
    try testing.expect(try canWrite("/f"));
}

test "canWrite: overlay returns true" {
    try preparePool();
    try permtrie.add("/f", Mode.dir); // dir has w=overlay
    try testing.expect(try canWrite("/f"));
}

test "canWrite: ask returns false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .ask, .x = .allow });
    try testing.expectEqual(false, try canWrite("/f"));
}

test "canWrite: no rule returns false" {
    try preparePool();
    try testing.expectEqual(false, try canWrite("/nope"));
}

// ── canExecute ──────────────────────────────────────────────────────────────

test "canExecute: deny returns false" {
    try preparePool();
    // file has x=allow by default, so use explicit deny
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .deny, .w = .overlay, .x = .deny });
    try testing.expectEqual(false, try canExecute("/f"));
}

test "canExecute: allow returns true" {
    try preparePool();
    try permtrie.add("/f", Mode.dir); // dir has x=allow
    try testing.expect(try canExecute("/f"));
}

test "canExecute: ask returns false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .overlay, .x = .ask });
    try testing.expectEqual(false, try canExecute("/f"));
}

test "canExecute: no rule returns false" {
    try preparePool();
    try testing.expectEqual(false, try canExecute("/nope"));
}

// ── showMetadata ────────────────────────────────────────────────────────────

test "showMetadata: hidden path → false" {
    try preparePool();
    try testing.expectEqual(false, try showMetadata("/hidden"));
}

test "showMetadata: visible path → true" {
    try preparePool();
    try permtrie.add("/vis", Mode.dir);
    try testing.expect(try showMetadata("/vis"));
}

// ── canPassthrough ──────────────────────────────────────────────────────────

test "canPassthrough: all conditions met → true" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow });
    try testing.expect(try canPassthrough("/f"));
}

test "canPassthrough: overlay write → false" {
    try preparePool();
    try permtrie.add("/f", Mode.dir); // w=overlay
    try testing.expectEqual(false, try canPassthrough("/f"));
}

test "canPassthrough: invisible → false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .invisible, .r = .allow, .w = .allow, .x = .allow });
    try testing.expectEqual(false, try canPassthrough("/f"));
}

test "canPassthrough: read ask → false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .ask, .w = .allow, .x = .allow });
    try testing.expectEqual(false, try canPassthrough("/f"));
}

test "canPassthrough: write ask → false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .ask, .x = .allow });
    try testing.expectEqual(false, try canPassthrough("/f"));
}

test "canPassthrough: execute ask → false" {
    try preparePool();
    try permtrie.add("/f", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .ask });
    try testing.expectEqual(false, try canPassthrough("/f"));
}

test "canPassthrough: no rule → false" {
    try preparePool();
    try testing.expectEqual(false, try canPassthrough("/nope"));
}

test "canPassthrough: child inheriting passthrough root → true" {
    try preparePool();
    try permtrie.add("/", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow });
    try testing.expect(try canPassthrough("/child"));
    try testing.expect(try canPassthrough("/child/grandchild"));
}

test "canPassthrough: child overrides passthrough with non-passthrough → false" {
    try preparePool();
    try permtrie.add("/", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow });
    try permtrie.add("/child", Mode.dir); // overlay write
    try testing.expectEqual(false, try canPassthrough("/child"));
    // But sibling still inherits passthrough from root
    try testing.expect(try canPassthrough("/sibling"));
}

// ── Integration: exhaustive prefix enumeration ─────────────────────────────

test "evaluate: exhaustive prefix walks" {
    try preparePool();

    // Build a tree:
    //   /       → dir    (visible_raw, r=allow, w=overlay, x=allow)
    //   /a      → file   (visible_raw, r=deny,  w=overlay, x=allow)
    //   /a/b    → dir
    //   /a/b/c  → file
    //   /x      → (no rule, falls through to /)
    const root = Mode.dir;
    const a_mode = Mode.file;
    const ab_mode = Mode.dir;
    const abc_mode = Mode.file;

    try permtrie.add("/", root);
    try permtrie.add("/a", a_mode);
    try permtrie.add("/a/b", ab_mode);
    try permtrie.add("/a/b/c", abc_mode);

    // Walk exhaustive prefixes
    try expectModeEqual(root, (try evaluate("/")).?);
    try expectModeEqual(a_mode, (try evaluate("/a")).?);
    try expectModeEqual(ab_mode, (try evaluate("/a/b")).?);
    try expectModeEqual(abc_mode, (try evaluate("/a/b/c")).?);
    try expectModeEqual(abc_mode, (try evaluate("/a/b/c/d")).?);
    try expectModeEqual(ab_mode, (try evaluate("/a/b/x")).?);
    try expectModeEqual(a_mode, (try evaluate("/a/x")).?);
    try expectModeEqual(a_mode, (try evaluate("/a/x/y")).?);
    try expectModeEqual(root, (try evaluate("/other")).?);
    try expectModeEqual(root, (try evaluate("/x")).?);
}

// ── Integration: large depth without allocation ────────────────────────────

test "evaluate: deep path walks without allocation" {
    try preparePool();

    // Build a chain: /a/b/c/d/e/f/g/h/i/j/k/l/m
    try permtrie.add("/", Mode.dir);
    try permtrie.add("/a/b/c/d/e/f/g/h/i/j/k/l/m", Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow });

    // The longest-prefix should find the deep rule.
    const result = try evaluate("/a/b/c/d/e/f/g/h/i/j/k/l/m");
    try testing.expect(result != null);
    try expectModeEqual(
        Mode{ .k = .visible_raw, .r = .allow, .w = .allow, .x = .allow },
        result.?,
    );

    // The ancestor '/a/b/c' should inherit from '/'
    try expectModeEqual(Mode.dir, (try evaluate("/a/b/c")).?);
}

// ── Edge: single-component paths ───────────────────────────────────────────

test "evaluate: single component paths" {
    try preparePool();
    try permtrie.add("/usr", Mode.dir);
    try permtrie.add("/usr/bin", Mode.file);
    try permtrie.add("/usr/bin/ls", Mode.dir);

    try expectModeEqual(Mode.dir, (try evaluate("/usr")).?);
    try expectModeEqual(Mode.file, (try evaluate("/usr/bin")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/usr/bin/ls")).?);
}

// ── Edge: root-only trie ───────────────────────────────────────────────────

test "evaluate: only root rule set" {
    try preparePool();
    try permtrie.add("/", Mode.dir);
    // All paths should inherit root
    try expectModeEqual(Mode.dir, (try evaluate("/anything")).?);
    try expectModeEqual(Mode.dir, (try evaluate("/very/deep/path")).?);
}
