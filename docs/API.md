# permbox-fuse public API

This project exports two Zig modules:

- `permtrie`: a persistent, concurrency-safe permission trie.
- `permfuse`: an embeddable FUSE driver using that trie.

Both modules use `std.Io`. Paths passed to policy operations are expected to be
normalized absolute paths beginning with `/`.

## Adding the modules

```zig
const dep = b.dependency("permbox_fuse", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("permtrie", dep.module("permtrie"));
exe.root_module.addImport("permfuse", dep.module("permfuse"));
```

## `permtrie`

```zig
const permtrie = @import("permtrie");
```

The module value itself is the trie type. It owns its backing file descriptor
and contains an internal `std.Io.RwLock`.

### `Mode`

`Mode` is a packed byte containing four two-bit fields:

```zig
const mode: permtrie.Mode = .{
    .k = .visible_raw,
    .r = .allow,
    .w = .overlay,
    .x = .ask,
};
```

| Field | Type | Values |
|---|---|---|
| `k` | `Mode.K` | `midway`, `visible_raw`, `visible_virtual`, `invisible` |
| `r` | `Mode.A` | `deny`, `ask`, `allow`, `_reserved` |
| `w` | `Mode.W` | `deny`, `ask`, `allow`, `overlay` |
| `x` | `Mode.A` | `deny`, `ask`, `allow`, `_reserved` |

`midway` is internal and must not be used as an explicit rule.
`Mode.dir` and `Mode.file` are supplied as convenient defaults.

### Initialization and ownership

```zig
var trie = try permtrie.init(io, fd);
defer trie.deinit();
```

`init(io, fd)` opens or initializes the binary trie stored in `fd`. On success,
the trie owns `fd`; `deinit()` unmaps the pool and closes it. If initialization
fails, ownership remains with the caller.

Do not copy an initialized trie value. Pass it by pointer.

### Rule lookup

```zig
const effective = try trie.get("/home/user/file");
const explicit = try trie.getExact("/home/user/file");
```

- `get(path)` returns the exact rule or the nearest slash-delimited ancestor.
- `getExact(path)` returns only a rule explicitly stored at `path`.
- Both return `null` when no applicable rule exists.
- Both take the shared side of the internal lock.

### Rule mutation

```zig
try trie.add("/home/user", mode);
const old_mode = try trie.del("/home/user");
trie.reset();
```

- `add(path, mode)` inserts or replaces an explicit rule.
- `del(path)` removes an explicit rule and returns its prior mode.
- `reset()` removes every rule.
- Mutations take the exclusive lock. `add` and `del` request a binary-backing
  sync before unlocking. A sync failure is logged as a non-critical persistence
  error; it is not returned after the in-memory/mmap mutation has committed.
- `reset` currently performs best-effort pool shrinking.

### Atomic groups

For multiple operations under one exclusive critical section:

```zig
trie.lockWrite();
defer trie.unlockWrite();

try trie.addLocked("/a", mode_a);
try trie.addLocked("/b", mode_b);
_ = try trie.delLocked("/old");
const current = try trie.getExactLocked("/a");
```

Available locked operations are:

- `getLocked`
- `getExactLocked`
- `addLocked`
- `delLocked`

They do not acquire the lock themselves. Calling them without holding the write
lock is invalid. Each locked mutation currently requests a sync after its
change, with sync failures logged rather than returned. The group prevents
readers and other writers from observing intermediate policy states, but an
error does not roll back preceding changes.

### Text serialization

```zig
const text = try trie.toText(allocator);
defer allocator.free(text);

try trie.replaceFromText(allocator,
    \\fs {
    \\  "/": access,overlay-w,ALWAYS-allow-rx {
    \\    "home/user": empty,allow-rw,deny-x
    \\  }
    \\}
);
```

- `toText(allocator)` returns an allocator-owned canonical `fs {}` block.
- `replaceFromText(allocator, text)` parses either a complete `fs {}` block or
  flat quoted entries and replaces the binary trie.
- Parsing happens before the exclusive lock is acquired, so malformed input
  leaves the existing trie unchanged.
- Output is bytewise sorted and may flatten the original nesting.
- Comments, semicolons, nested paths, quoted escapes, and combined permission
  forms such as `allow-rwx` are accepted.
- `TextError` exposes the text parser/formatter error set.

The textual flags map as follows:

| Text | Binary value |
|---|---|
| `access` | `k = .visible_raw` |
| `empty` | `k = .visible_virtual` |
| `no-access` | `k = .invisible` |
| `deny-r`, `allow-r`, `ALWAYS-allow-r` | `r = deny`, `ask`, `allow` |
| `deny-w`, `allow-w`, `ALWAYS-allow-w`, `overlay-w` | corresponding `w` value |
| `deny-x`, `allow-x`, `ALWAYS-allow-x` | `x = deny`, `ask`, `allow` |

## `permfuse`

```zig
const permfuse = @import("permfuse");
```

`permfuse` provides the mount driver, policy operations, permission callback
types, overlay application, and an optional command-line option parser.

Only one `Driver` may be initialized in a process at a time.

### Exported policy types

`permfuse.Mode` is the same packed type as `permtrie.Mode`.

```zig
pub const Operation = enum { read, write, execute };
pub const AskDecision = enum { deny, allow };

pub const AskRequest = struct {
    path: []const u8,
    operation: Operation,
    current: Mode,
};
```

An ask callback has this shape:

```zig
fn ask(
    context: ?*anyopaque,
    io: std.Io,
    request: permfuse.AskRequest,
) anyerror!permfuse.AskDecision
```

The callback is invoked only for an `ask` operation after the handle has
re-read the trie once. Approval updates both that handle's policy snapshot and
the explicit trie rule.

### Driver configuration

```zig
const Config = permfuse.Config{
    .backing_path = "/real/root",
    .policy_path = "/var/lib/permbox/policy.bin",
    .state_path = "/var/lib/permbox/session",
    .passthrough = true,
    .ask_context = context,
    .ask_fn = ask,
};
```

| Field | Meaning |
|---|---|
| `backing_path` | NUL-terminated directory exposed as the filesystem root |
| `policy_path` | NUL-terminated persistent binary-trie file |
| `state_path` | Optional durable sparse-overlay session directory |
| `passthrough` | Request kernel FUSE passthrough for fully allowed handles |
| `ask_context` | Opaque pointer passed to `ask_fn` |
| `ask_fn` | Optional permission callback |

Configuration paths are copied or consumed during initialization as needed;
the caller does not need to retain the `Config`.

### Driver lifetime

```zig
var driver: permfuse.Driver = undefined;
try driver.init(io, config);
defer driver.deinit();
```

- Initialize the driver in its final storage location.
- Do not move or copy it while `mount` is running; libfuse retains a pointer to
  its callback state.
- `deinit()` must be called only after `mount()` has returned.
- Initialization opens the backing directory, opens or creates the policy
  trie, and resumes or creates the configured overlay session.

### Policy operations

```zig
const exact = try driver.getRule("/path");
const effective = try driver.evaluate("/path/child");
try driver.setRule("/path", mode);
const removed = try driver.removeRule("/path");
```

- `getRule` is exact lookup.
- `evaluate` includes slash-delimited ancestor inheritance.
- `setRule` inserts or replaces a rule.
- `removeRule` removes and returns an explicit rule.

For a grouped update:

```zig
try driver.updateRules(&.{
    .{ .set = .{ .path = "/a", .mode = mode_a } },
    .{ .remove = "/old" },
});
```

`updateRules` holds the trie write lock for the entire group. Readers cannot
observe a partial group, but an error does not roll back earlier updates.

Policy text conversion is also available directly through the driver:

```zig
const text = try driver.policyToText(allocator);
defer allocator.free(text);

try driver.replacePolicyFromText(allocator, new_fs_block);
```

### Mounting

```zig
try driver.mount(allocator, "/mnt/box", .{
    .io_uring = true,
    .arguments = &.{ "-f" },
});
```

`MountOptions` contains:

- `io_uring`: enables the libfuse `io_uring` option by default.
- `arguments`: additional NUL-terminated libfuse arguments. Their storage must
  remain valid until `mount` returns.

`mount` runs the multithreaded low-level FUSE loop and blocks until unmounted.
Only one mount may run for a driver.

From another thread:

```zig
driver.requestUnmount();
```

`requestUnmount()` is thread-safe and asks the active FUSE session to exit. It
does nothing when no mount is active.

Passthrough is requested only for handles whose snapshotted mode fully allows
raw read, write, and execute access. Overlay, denied, and ask operations remain
in userspace.

### Durable overlay application

When `state_path` is configured, overlay writes are stored in a durable,
resumable session. Apply them after the mount has stopped:

```zig
const result = try driver.applyOverlay(allocator, .{
    .max_files = null,
    .remove_applied = false,
});

if (result.complete()) {
    // No unapplied files remain.
}
```

`ApplyOptions`:

- `max_files`: maximum number of previously unapplied files to process; `null`
  means no limit.
- `remove_applied`: remove applied data/path records after the durable
  checkpoint is written.

`ApplyResult`:

- `applied`: entries applied during this call.
- `skipped`: entries already at their durable checkpoint.
- `remaining`: entries still requiring application.
- `complete()`: equivalent to `remaining == 0`.

Application is journaled and idempotent. It can resume after interruption and
after partial, bounded runs. `applyOverlay` rejects calls while mounted or when
no overlay session is configured.

### `OverlaySession`

`permfuse.OverlaySession` exposes the lower-level durable session API:

- `OverlaySession.open(io, path, create)`
- `deinit()`
- `register(path)`
- `duplicateDataFd()`
- `duplicatePathsFd()`
- `apply(allocator, backing_path, options)`

The returned duplicate file descriptors are caller-owned. Most consumers
should use `Driver` rather than manipulate session storage directly.

### Option parsing

`permfuse.options.parse(argv)` parses the test-harness style command line:

- `--backing=PATH`
- `--policy=PATH`
- `--state=PATH`
- `--no-io-uring`
- `--no-passthrough`
- first positional argument as the mountpoint

It returns `permfuse.options.Config`, whose strings are owned by an internal
arena. Call `Config.deinit()` when finished.

This parser is also used by the installed interactive `permfuse` command. The
core library can still be embedded without invoking that command.

### Low-level C namespace

`permfuse.c` re-exports the generated libfuse/libc C namespace used by the
driver. It is available for integration code that must interoperate with
libfuse directly, but it is not required for normal `Driver` use.
