# permbox-fuse

Policy-aware, low-level FUSE 3 filesystem for Linux. It maps a backing
directory into one mount and evaluates the memory-mapped permission trie for
every namespace and open operation.

The daemon targets libfuse 3.18. Kernel FUSE-over-io_uring is enabled by
default. Files whose effective rule is `visible_raw` with read, write, and
execute all set to `allow` use kernel FUSE passthrough for read, write, splice,
and mmap. Restricted files stay in userspace and are checked against their
longest-prefix trie rule.

## Build

```sh
zig build -Doptimize=ReleaseSafe
zig build test -Doptimize=ReleaseSafe
```

The current build requires Linux, libfuse 3.18 headers/libraries, and glibc.
Passthrough also requires kernel support, `CONFIG_FUSE_PASSTHROUGH`, and
`CAP_SYS_ADMIN`. If passthrough negotiation fails, the daemon retains the same
policy behavior using userspace I/O.

## Run

```sh
zig-out/bin/permbox-fuse \
  --backing=/absolute/backing/root \
  --policy=/absolute/policy.trie \
  --state=/absolute/state/directory \
  /absolute/mountpoint
```

`--state` is optional, but is required to write files governed by `overlay-w`.
It names a durable, versioned session directory. Restarting with the same
directory resumes the partial session. Sparse data extents override the backing
file and holes fall through to it. `--no-io-uring` and `--no-passthrough`
provide explicit compatibility fallbacks. Other arguments are passed to
libfuse.

Unlisted and invisible paths return as missing. `deny` and `ask` fail closed;
the userspace confirmation control plane is not part of this daemon yet.
Directory creation/removal and regular-file creation/removal are allowed only
under `allow-w`; renames, links, metadata mutations, and virtual-only objects
currently fail closed.

## Embedding

The package exports both `permbox` (the driver API) and `permtrie` (the raw
trie). A dependent `build.zig` can import the driver with:

```zig
const dep = b.dependency("permbox_fuse", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("permbox", dep.module("permbox"));
```

Initialize the driver in-place because its FUSE state retains pointers to the
driver's `std.Io.RwLock` and overlay session:

```zig
const std = @import("std");
const permbox = @import("permbox");

fn ask(
    context: ?*anyopaque,
    io: std.Io,
    request: permbox.AskRequest,
) !permbox.AskDecision {
    _ = context;
    _ = io;
    std.log.info("permission requested: {s} {t}", .{
        request.path,
        request.operation,
    });
    return .allow;
}

var driver: permbox.Driver = undefined;
try driver.init(io, .{
    .backing_path = "/srv/root",
    .policy_path = "/run/app/policy.trie",
    .state_path = "/run/app/session",
    .ask_fn = ask,
});
defer driver.deinit();

try driver.setRule("/", permbox.Mode.dir);
try driver.mount(allocator, "/run/app/mount", .{});
```

`mount` is blocking and `requestUnmount` is thread-safe; applications can run
the mount with `std.Io.concurrent` when they need other work on the calling
task. One driver may be active in a process because the mmap trie currently has
one process-global pool.

An open snapshots its effective rule. Allowed operations stay on an atomic
one-byte fast path and fully allowed files remain eligible for kernel
passthrough. For an `ask` snapshot, the operation re-checks the trie once before
calling `ask_fn`. Approval stores an explicit allow rule and updates that open
handle. This avoids duplicate prompts when another open resolved the rule.

`applyOverlay` copies exact journaled write ranges back to the backing
filesystem only while the driver is unmounted. Each target is synced before
its range-journal offset is checkpointed in `apply.log`, making retries
idempotent after interruption and allowing later writes to the same path.
`ApplyOptions.max_files` permits bounded/partial application; reopening the
session and calling it again resumes at the first uncheckpointed entry.
`OverlaySession.open` exposes the same recovery/apply machinery without
mounting FUSE.
