# Public API

The package exports two Zig modules:

- `permtrie`: concurrent, mmap-backed longest-prefix policy storage.
- `permfuse`: private OverlayFS lifecycle and policy-aware FUSE driver.

All APIs are alpha and intentionally have no compatibility guarantees.

## `permtrie`

### `Access`

```zig
pub const Access = enum(u2) {
    whiteout,
    r,
    rw,
    ask,
};
```

### Opening

```zig
pub fn init(io: std.Io, fd: std.c.fd_t) !permtrie
pub fn deinit(trie: *permtrie) void
```

The trie owns `fd` after successful initialization. Its mmap may move when the
pool grows, but the exported value can remain at a stable address.

### Rules

```zig
pub fn add(trie: *permtrie, path: []const u8, access: Access) !void
pub fn del(trie: *permtrie, path: []const u8) !Access
pub fn get(trie: *permtrie, path: []const u8) !?Access
pub fn getExact(trie: *permtrie, path: []const u8) !?Access
```

`get` returns the nearest explicit slash-component ancestor. `getExact`
ignores inherited rules. Public operations synchronize internally with a
`std.Io.RwLock`.

For a transaction:

```zig
trie.lockWrite();
defer trie.unlockWrite();

try trie.addLocked("/a", .r);
try trie.addLocked("/b", .rw);
```

The locked variants must only be called while the write lock is held.

### Text conversion

```zig
pub fn parseAccessText(text: []const u8) !Access
pub fn toText(trie: *permtrie, allocator: Allocator) ![]u8
pub fn replaceFromText(
    trie: *permtrie,
    allocator: Allocator,
    text: []const u8,
) !void
```

The caller owns the returned text. `replaceFromText` parses before locking and
then replaces all rules under one write-side critical section.

## `permfuse`

### Policy types

```zig
pub const Access = permtrie.Access;

pub const Operation = enum {
    metadata,
    read,
    write,
    create,
};

pub const AskRequest = struct {
    path: []const u8,
    operation: Operation,
};

pub const AskFn = *const fn (
    context: ?*anyopaque,
    io: std.Io,
    request: AskRequest,
) anyerror!Access;
```

An ask callback must return `whiteout`, `r`, or `rw`. It runs before a handle
or mutation is opened. Returning `ask` rejects the operation.

### Driver configuration

```zig
pub const Config = struct {
    lower_path: [:0]const u8,
    policy_path: [:0]const u8,
    session_path: [:0]const u8,
    passthrough: bool = true,
    ask_context: ?*anyopaque = null,
    ask_fn: ?AskFn = null,
    overlay: OverlayMountOptions = .{},
};
```

- `lower_path` is the original tree.
- `policy_path` is the mmap-backed trie file.
- `session_path` contains `upper`, `work`, `merged`, and the exclusive lock.
- `passthrough` requests kernel FUSE passthrough.

The paths are copied during initialization.

```zig
pub fn Driver.init(driver: *Driver, io: std.Io, config: Config) !void
pub fn Driver.deinit(driver: *Driver) void
```

One driver can be active in a process because the policy trie currently uses
one process-global instance.

### Policy updates

```zig
pub fn getRule(driver: *Driver, path: []const u8) !?Access
pub fn evaluate(driver: *Driver, path: []const u8) !?Access
pub fn setRule(driver: *Driver, path: []const u8, access: Access) !void
pub fn removeRule(driver: *Driver, path: []const u8) !Access
pub fn updateRules(driver: *Driver, updates: []const RuleUpdate) !void
pub fn policyToText(driver: *Driver, allocator: Allocator) ![]u8
pub fn replacePolicyFromText(
    driver: *Driver,
    allocator: Allocator,
    text: []const u8,
) !void
```

`updateRules` holds the policy write lock for the complete update list.

### Mounting

```zig
pub const MountOptions = struct {
    io_uring: bool = true,
    arguments: []const [:0]const u8 = &.{},
};

pub fn mount(
    driver: *Driver,
    allocator: Allocator,
    mountpoint: [:0]const u8,
    options: MountOptions,
) !void

pub fn requestUnmount(driver: *Driver) void
```

`mount` creates the private OverlayFS mount, starts the multithreaded low-level
FUSE loop, and blocks. On exit it destroys all FUSE handles before unmounting
the private OverlayFS.

The FUSE mount uses `default_permissions`. Returned metadata comes from the
private merged tree, so caller UID/GID, mode, ACL, sticky-directory, and
execute checks remain kernel checks.

### Apply and discard

```zig
pub const ApplyOptions = struct {
    max_entries: ?usize = null,
};

pub const ApplyResult = struct {
    applied: usize,
    remaining: usize,

    pub fn complete(result: ApplyResult) bool;
};

pub fn apply(driver: *Driver, options: ApplyOptions) !ApplyResult
pub fn discard(driver: *Driver, relative_path: []const u8) !void
```

Both calls reject an active mount. Apply drains at most `max_entries` upper
leaf entries and can be called again to resume. `discard` accepts a canonical
relative path beneath the upper root.

### Direct session API

```zig
pub fn OverlaySession.open(io: std.Io, path: [:0]const u8) !OverlaySession
pub fn OverlaySession.mount(
    session: *OverlaySession,
    lower: [:0]const u8,
    options: OverlayMountOptions,
) !void
pub fn OverlaySession.unmount(session: *OverlaySession) !void
pub fn OverlaySession.apply(
    session: *OverlaySession,
    lower: [:0]const u8,
    options: ApplyOptions,
) !ApplyResult
pub fn OverlaySession.discard(
    session: *OverlaySession,
    relative_path: []const u8,
) !void
pub fn OverlaySession.deinit(session: *OverlaySession) void
```

The session holds an exclusive advisory lock until deinitialized.
