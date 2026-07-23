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
Overlay data is stored in sparse files; data extents override the backing file
and holes fall through to it. `--no-io-uring` and `--no-passthrough` provide
explicit compatibility fallbacks. Other arguments are passed to libfuse.

Unlisted and invisible paths return as missing. `deny` and `ask` fail closed;
the userspace confirmation control plane is not part of this daemon yet.
Directory creation/removal and regular-file creation/removal are allowed only
under `allow-w`; renames, links, metadata mutations, and virtual-only objects
currently fail closed.
