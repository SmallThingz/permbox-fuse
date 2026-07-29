# permfuse

`permfuse` is an embeddable Linux filesystem policy driver used by Permbox.
It mounts a private kernel OverlayFS and exposes that merged tree through a
small low-level FUSE filesystem.

OverlayFS handles copy-up, whiteouts, opaque directories, sparse files, mmap,
links, rename, and ordinary filesystem behavior. The FUSE layer decides
whether each path is hidden, read-only, writable, or requires a synchronous
decision.

## Policy

Every explicit trie rule is one of:

| Rule | Meaning |
| --- | --- |
| `whiteout` | The path appears not to exist |
| `r` | Metadata and read-only access |
| `rw` | Reads and mutations, subject to Unix permissions |
| `ask` | Resolve to one of the other three before the operation |

Rules use longest-component-prefix inheritance. There is no separate execute
rule. Owner, group, mode, POSIX ACL, sticky-directory, and execute checks are
normal kernel permission checks.

The text form is:

```text
fs {
  "/":rw {
    "usr":r
    "home/me":rw
    "home/me/.ssh":ask
    "secret":whiteout
  }
}
```

## Build and test

The installed CLI uses LLVM by default:

```sh
zig build
```

Run both required test configurations:

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
```

Linux, glibc, and libfuse 3.18 are required. Kernel OverlayFS mounting and
FUSE passthrough require the corresponding kernel features and privileges.
When passthrough is unavailable, file I/O uses the normal FUSE path.

## Library use

```zig
const std = @import("std");
const permfuse = @import("permfuse");

fn ask(
    context: ?*anyopaque,
    io: std.Io,
    request: permfuse.AskRequest,
) !permfuse.Access {
    _ = context;
    _ = io;
    std.log.info("policy request: {s} {t}", .{
        request.path,
        request.operation,
    });
    return .r;
}

var driver: permfuse.Driver = undefined;
try driver.init(io, .{
    .lower_path = "/srv/root",
    .policy_path = "/run/permbox/policy.trie",
    .session_path = "/run/permbox/session",
    .ask_fn = ask,
});
defer driver.deinit();

try driver.setRule("/", .rw);
try driver.setRule("/etc", .r);
try driver.mount(allocator, "/run/permbox/mount", .{});
```

`mount` blocks until unmounted. Run it with `std.Io.concurrent` or another
thread when the caller needs to continue. `requestUnmount` is thread-safe.
The driver must remain at a stable address while mounted.

The private OverlayFS is mounted only for the duration of `Driver.mount`.
After it returns, changes can be applied or discarded:

```zig
const result = try driver.apply(.{ .max_entries = 100 });
if (!result.complete()) {
    // A later call resumes from the remaining upper entries.
}

try driver.discard("tmp/generated");
```

Apply publishes through destination-side temporary names, syncs the result and
destination directory, then removes the corresponding upper entry. The upper
tree is therefore the restart checkpoint.

## CLI

```sh
zig-out/bin/permfuse \
  --lower=/absolute/lower \
  --policy=/absolute/policy.trie \
  --session=/absolute/session \
  /absolute/mountpoint
```

Interactive commands:

```text
show
get /path
set /path whiteout|r|rw|ask
del /path
load policy.fs
save policy.fs
unmount
apply 100
discard /path
quit
```

Trie conversion does not mount a filesystem:

```sh
permfuse trie to-text policy.trie policy.fs
permfuse trie from-text policy.fs policy.trie
```

See [docs/API.md](docs/API.md) for the exported API and [PLAN.md](PLAN.md) for
the implementation design and remaining acceptance work.
