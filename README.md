# permbox-fuse

A `fuse3` fs that supports fine grained access control over directories and files allow the user to selectively allow and dynamically change then black/white lists

Current version targets fuse3.1; plan it to change this to fuse3.15 for passthrough once the implementation is complete

## Permission Control
Permission control is handled through a radix trie of paths that can be live updated and is serialized to disk on unmount.
