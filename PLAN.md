# permfs design

## Status

The OverlayFS migration is implemented. This file records the current design
and the remaining verification work. It is not a compatibility roadmap.

Permfuse is a library with one debugging CLI. There is no separate mount-test
program. The CLI calls the same public `Driver` API as an embedding project.

## Architecture

```text
lower directory
       +
session upper and work directories
       |
       v
private kernel OverlayFS mount
       |
       v
policy FUSE mount
       |
       v
sandboxed process
```

Kernel OverlayFS owns copy-up, whiteouts, opaque directories, links, sparse
files, truncation, rename, mmap, and ordinary filesystem semantics. The FUSE
layer owns policy resolution, namespace filtering, interactive decisions, and
passthrough registration.

The four public access states are:

- `whiteout`: the path appears not to exist;
- `r`: metadata and read-only access are allowed;
- `rw`: reads and mutations are allowed;
- `ask`: a synchronous callback must choose one of the other states before the
  operation proceeds.

Rules use longest-component-prefix inheritance. Unix ownership, mode, ACL,
sticky-directory, and execute checks remain kernel checks.

## Operation rules

- Lookup, metadata, readlink, `O_PATH`, and directory enumeration require `r`
  or `rw`.
- Hidden children are omitted from directory enumeration.
- `O_RDONLY` requires `r` or `rw`.
- `O_WRONLY`, `O_RDWR`, `O_TRUNC`, and mutations require `rw`.
- Namespace creation and removal require a writable parent.
- Every `ask` is resolved before opening a handle.
- An open handle retains its resolved policy snapshot.
- A later policy change affects new operations and handles.
- Release and ordinary handle I/O do not acquire the policy lock.
- Eligible resolved handles use descriptors from the private merged mount for
  FUSE passthrough.

Every callback forwards filesystem ownership and type behavior to OverlayFS
where possible. The global inode-map lock is never held across filesystem I/O.

## Session state

The session contains `upper`, `work`, and a temporary `merged` mountpoint.
Upper entries are both changed data and restart checkpoints. Apply publishes
one upper entry at a time, syncs the destination and its parent, and removes
the upper entry only after publication is durable. A later apply resumes from
the remaining entries.

Whiteouts, opaque directories, regular files, directories, symlinks, special
files, and hard-link groups are interpreted from OverlayFS upper state.
Bounded apply counts leaf entries; a hard-link group completes together.
Discard removes one pending relative path.

Mount, apply, and discard are mutually exclusive for a driver. The session
lock prevents two processes from operating on the same session.

## Version policy

- Package version: `0.0.0`.
- Trie on-disk format version: `0`.
- Text policy format: unversioned `fs { ... }`.
- Overlay session: no independent schema version; kernel upper entries are the
  durable representation.

The libfuse API level is `318`. This selects libfuse 3.18 declarations and is
not a permfs version.

The project is in alpha. No migration code or backward-compatibility branches
are retained when an internal representation changes.

## Verification

Required checks:

```sh
zig build test
zig build test -Doptimize=ReleaseSafe
zig build
```

Unit tests cover trie persistence and endian repair, text round trips, policy
inheritance, concurrent ask resolution, upper-entry apply and resume, hard
links, whiteouts, opaque directories, and discard.

Privileged integration coverage should continue to exercise:

- all open flag combinations, mmap, truncate, fallocate, and sparse files;
- hidden lookup and directory filtering;
- rename, hard links, symlinks, FIFOs, devices, and sockets;
- ACLs, supplementary groups, setgid directories, and sticky directories;
- concurrent lookup, forget, release, policy update, and unmount;
- passthrough and userspace-I/O equivalence;
- interrupted and bounded apply;
- supported and rejected OverlayFS mount options.
