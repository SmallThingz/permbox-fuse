# permfuse

Embeddable, policy-aware low-level FUSE 3 library for Linux. It is the
filesystem driver used by permbox, not a standalone daemon or application.
It maps a backing directory into one mount and evaluates the memory-mapped
permission trie for namespace and open operations.

The daemon targets libfuse 3.18. Kernel FUSE-over-io_uring is enabled by
default. Files whose effective rule is `visible_raw` with read, write, and
execute all set to `allow` use kernel FUSE passthrough for read, write, splice,
and mmap. Restricted files stay in userspace and are checked against their
longest-prefix trie rule.

## Validate

```sh
zig build test -Doptimize=ReleaseSafe
```

The library requires Linux, libfuse 3.18 headers/libraries, and glibc.
Passthrough also requires kernel support, `CONFIG_FUSE_PASSTHROUGH`, and
`CAP_SYS_ADMIN`. If passthrough negotiation fails, the driver retains the same
policy behavior using userspace I/O.

## Embedding

The package exports both `permfuse` (the driver API) and `permtrie` (the
concurrency-safe trie). A dependent `build.zig` can import the driver with:

```zig
const dep = b.dependency("permbox_fuse", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("permfuse", dep.module("permfuse"));
```

The exported `permtrie` module can round-trip its mmap-backed binary policy to
the permbox filesystem configuration syntax:

```zig
const text = try trie.toText(allocator);
defer allocator.free(text);

try trie.replaceFromText(allocator,
    \\fs {
    \\  "/": access,overlay-w,ALWAYS-allow-rx {
    \\    "home/me": empty,allow-rw,deny-x
    \\  }
    \\}
);
```

`toText` emits a canonical, bytewise-sorted `fs {}` block. It may flatten the
input hierarchy, but preserves every explicit path and all current trie mode
bits.

See [docs/API.md](docs/API.md) for the complete public API reference for both
`permtrie` and `permfuse`.

The implementation is described in detail in
[docs/architecture.pdf](docs/architecture.pdf). Its LaTeX source is
[docs/architecture.tex](docs/architecture.tex).

Initialize the driver in-place and do not move it while `mount` is running,
because libfuse retains a pointer to its callback state. Configuration paths
are copied during initialization:

```zig
const std = @import("std");
const permfuse = @import("permfuse");

fn ask(
    context: ?*anyopaque,
    io: std.Io,
    request: permfuse.AskRequest,
) !permfuse.AskDecision {
    _ = context;
    _ = io;
    std.log.info("permission requested: {s} {t}", .{
        request.path,
        request.operation,
    });
    return .allow;
}

var driver: permfuse.Driver = undefined;
try driver.init(io, .{
    .backing_path = "/srv/root",
    .policy_path = "/run/app/policy.trie",
    .state_path = "/run/app/session",
    .ask_fn = ask,
});
defer driver.deinit();

try driver.setRule("/", permfuse.Mode.dir);
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

## Manual mount harness

There is no installed executable. For manual integration testing only:

```sh
zig build run-mount-test -- \
  --backing=/absolute/backing/root \
  --policy=/absolute/policy.trie \
  --state=/absolute/state/directory \
  /absolute/mountpoint
```

`--state` resumes durable overlay state. `--no-io-uring` and
`--no-passthrough` select compatibility paths; remaining options are passed to
libfuse.
