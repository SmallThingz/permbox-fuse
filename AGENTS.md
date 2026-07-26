# permbox-fuse3 contributor notes

## Commands

- Prefix shell commands with `rtk` when it is installed. If it is unavailable,
  use the raw command and keep output scoped.
- Validate with `zig build test` and
  `zig build test -Doptimize=ReleaseSafe`.

## Trie invariants

- The mmap pool uses 1 KiB nodes. Node 0 is the block header and node 1 is the
  initial root; never treat index 0 as a live node.
- `Pool.resize` may move the mapping. Re-fetch every `*Node` from its index
  after an allocation that can resize the pool.
- An `idx_arr` slot is inline data when its bit is clear and a node index when
  its bit is set.
- Do not merge a node with `radix_len == 0`, or a remaining child that has
  children/inline data. Either changes `.this` lookup semantics.
- Deletion cleanup must use the direct parent from the last traversal step.
- Release only unpublished nodes from `errdefer`. Once linked into the trie,
  cleanup failures are non-critical and must be logged rather than freeing a
  live node.

## Concurrency and FUSE

- Use `std.Io` synchronization. The exported trie serializes every lookup and
  mutation internally; multi-rule and ask-resolution updates hold its write
  side for the complete transaction.
- Ordinary I/O uses the open handle's policy snapshot. An `ask` operation
  re-reads the trie once, then an approval updates both the explicit trie rule
  and that handle. Fully allowed handles remain eligible for passthrough.
- Keep global inode-map and per-inode critical sections short. Never hold the
  inode-map mutex across backing or overlay data I/O.
- Overlay session metadata and apply checkpoints are durable state. Changes to
  their format must remain restart-safe and either be backward compatible or
  use an explicit version.
