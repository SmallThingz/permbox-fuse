const std = @import("std");
const fuse_version = 31;

pub const c = @cImport({
    @cDefine("FUSE_USE_VERSION", std.fmt.comptimePrint("{d}", .{fuse_version}));
    @cInclude("/usr/include/fuse3/fuse.h");
    @cInclude("/usr/include/fuse3/fuse_log.h");
});
/// Retrieves metadata and file attributes for the path, mirroring a standard `stat` call.
///
/// Implementation Notes:
///   - The kernel/libfuse entirely ignore the `st_dev` and `st_blksize` fields you set.
///   - The `st_ino` field is ignored unless the `use_ino` mount option is passed. Even then,
///     libfuse and the kernel will still map it to a different internal identifier ("nodeid").
///
/// Parameters:
///   - stbuf: Target `stat` struct to populate. Must be zeroed out first.
///   - fi: Optional file info. Guaranteed `null` if the file is closed, but can also be `null`
///         even if the file is open. If present, `fi.fh` can bypass path lookups.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.ENOENT`).
fn getattr(path: [*:0]const u8, stbuf: *c.struct_stat, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Reads the target path of a symbolic link.
///
/// Implementation Notes:
///   - The `buf` must be filled with a null-terminated string containing the link target.
///   - The `size` argument includes the space required for the terminating null character.
///   - If the target path is too long to fit within `size`, it must be truncated.
///
/// Parameters:
///   - buf: Destination buffer to write the null-terminated target path into.
///   - size: Maximum capacity of the destination buffer, including the null terminator.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.ENOENT`).
fn readlink(path: [*:0]const u8, buf: [*]u8, size: size_t) callconv(.c) c_int {}

/// Create a file node for all non-directory, non-symlink nodes (e.g., FIFOs, device nodes).
///
/// Implementation Notes:
///    - If your filesystem defines a separate `create()` method, that will be called
///      instead of `mknod()` when creating regular files.
///    - Device Identifier Constraint: The `rdev` parameter contains valid major/minor device
///      numbers exclusively if the file type inside the `mode` bitmask evaluates strictly to
///      a character device (`S_ISCHR`) or a block device (`S_ISBLK`). If `mode` specifies
///      a regular file, named pipe (FIFO), or socket, the content of `rdev` is undefined/garbage
///      passed from the kernel and must be explicitly ignored by your implementation.
///
/// Parameters:
///    - path: The target path where the new file node will be created.
///    - mode: Permissions and file type information (e.g., `S_IFIFO`, `S_IFCHR`).
///    - rdev: Device identifier parameters, utilized exclusively if creating a device node.
///
/// Returns:
///    - `0` on success, or a negative C error code (e.g., `-c.ENOSPC`).
fn mknod(path: [*:0]const u8, mode: c.mode_t, rdev: c.dev_t) callconv(.c) c_int {}

/// Create a new directory.
///
/// Implementation Notes:
///   - The `mode` argument passed by the kernel may not have the directory type specification
///     bits set natively (i.e., `S_ISDIR(mode)` might return false).
///   - To obtain the correct, fully-qualified directory type bits, always bitwise-OR the
///     mode explicitly inside your implementation: `mode | c.S_IFDIR`.
///
/// Parameters:
///   - mode: The requested permission bits for the new directory.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EEXIST`).
fn mkdir(path: [*:0]const u8, mode: c.mode_t) callconv(.c) c_int {}

/// Remove (delete) a file node.
///
/// Implementation Notes:
///    - POSIX compliance dictates that unlinking an open file removes its visible path
///      while keeping its backing inode alive until the final file descriptor is closed.
///    - Because FUSE operates as a userspace network-like protocol, the kernel cannot
///      easily hide anonymous inodes. To resolve this, if a file is unlinked while actively
///      open, the kernel/libfuse triggers a "Silly Rename" mechanism—mutating the request
///      into a `rename` call that hides the file as `.fuse_hiddenXXXXXXXXXXXXXXXX`.
///    - Consequently, your `unlink` callback is executed immediately when the path is removed,
///      rather than being deferred. If your backend tracks objects strictly by path strings,
///      expect to see an immediate `unlink` (or hidden `rename`) followed by a `.release`
///      callback much later when the file descriptor finally closes.
///
/// Returns:
///    - `0` on success, or a negative C error code (e.g., `-c.ENOENT`).
fn unlink(path: [*:0]const u8) callconv(.c) c_int {}

/// Remove (delete) a directory.
///
/// Implementation Notes:
///    - Similar to `unlink`, if an application attempts to remove a directory that is
///      currently an active working directory or held open by a process stream, the kernel
///      will invoke this callback immediately rather than waiting for references to clear.
///    - If tracking directory lifecycles strictly by path vectors, ensure your backend
///      gracefully separates the immediate destruction of the namespace entry from the
///      eventual structural cleanup triggered by downstream `.releasedir` invocations.
///
/// Returns:
///    - `0` on success, or a negative C error code (e.g., `-c.ENOTEMPTY`).
fn rmdir(path: [*:0]const u8) callconv(.c) c_int {}

/// Create a symbolic link pointing to a target path.
///
/// Parameters:
///   - target: The existing path or contents that the symlink should point to.
///   - linkpath: The absolute path where the new symbolic link file itself is being created.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EEXIST`).
fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) callconv(.c) c_int {}

/// Rename a file or directory, optionally handling atomic flags.
///
/// Implementation Notes:
///    - If `flags` contains `c.RENAME_NOREPLACE`, you must fail and return `-c.EEXIST`
///      if `newname` already exists, rather than overwriting it.
///    - If `flags` contains `c.RENAME_EXCHANGE`, you must atomically swap `oldname`
///      and `newname`. Both paths must exist, and neither can be deleted during the swap.
///    - If `flags` contains `c.RENAME_WHITEOUT`, you must handle union/overlay filesystem
///      semantics. This requires atomically creating a "whiteout" device node (a character
///      device with `0,0` major/minor device numbers) at the source path (`oldname`) while
///      simultaneously moving the original file node to the destination path (`newname`).
///
/// Parameters:
///    - oldname: The existing source path of the file or directory being relocated.
///    - newname: The target destination path for the rename operation.
///    - flags: Bitmask modifier flags controlling rename behavior (e.g., `RENAME_NOREPLACE`).
///
/// Returns:
///    - `0` on success, or a negative C error code (e.g., `-c.EINVAL`).
fn rename(oldname: [*:0]const u8, newname: [*:0]const u8, flags: c_uint) callconv(.c) c_int {}

/// Create a hard link to an existing file.
///
/// Parameters:
///   - oldpath: The existing source file path to link against.
///   - newpath: The destination path where the new hard link will be created.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EMLINK`).
fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8) callconv(.c) c_int {}

/// Change the permission bits of a file or directory.
///
/// Parameters:
///   - mode: The new bitmask containing the target permissions.
///   - fi: Optional file info. Guaranteed `null` if the file is closed, but can also be
///         `null` even if the file is open. If present, it can bypass path-based lookups.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EPERM`).
fn chmod(path: [*:0]const u8, mode: c.mode_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Change the owner and group identifiers of a file or directory.
///
/// Implementation Notes:
///   - Unless `FUSE_CAP_HANDLE_KILLPRIV` has been explicitly disabled during initialization,
///     this method is expected to automatically clear/reset the `setuid` and `setgid`
///     permission bits upon a successful owner change.
///
/// Parameters:
///   - uid: The target user ID owner. If set to `-1` (or `c.uid_t)(-1)`), owner is unchanged.
///   - gid: The target group ID owner. If set to `-1` (or `c.gid_t)(-1)`), group is unchanged.
///   - fi: Optional file info. Guaranteed `null` if the file is closed, but can also be
///         `null` even if the file is open. If present, it can bypass path-based lookups.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EINVAL`).
fn chown(path: [*:0]const u8, uid: std.c.uid_t, gid: std.c.gid_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Change the size of a file.
///
/// Implementation Notes:
///   - Unless `FUSE_CAP_HANDLE_KILLPRIV` has been explicitly disabled during initialization,
///     this method is expected to automatically clear/reset the `setuid` and `setgid`
///     permission bits upon a successful file size modification.
///
/// Parameters:
///   - size: The target length of the file in bytes.
///   - fi: Optional file info. Guaranteed `null` if the file is closed, but can also be
///         `null` even if the file is open. If present, it can bypass path-based lookups.
///
/// Returns:
///   - `0` on success, or a negative C error code (e.g., `-c.EFBIG`).
fn truncate(path: [*:0]const u8, size: std.c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Opens a file and initializes file handles or caching strategies.
///
/// This callback is executed when an application requests a file descriptor. It serves as
/// the gateway for access control validation, custom file handle allocation, and performance
/// tuning parameter negotiation with the Linux kernel Virtual File System (VFS).
///
/// Implementation Mechanics & Rules:
///   - Filter Flags: File creation flags (O_CREAT, O_EXCL, O_NOCTTY) are stripped and
///     handled entirely by the kernel before this callback is reached.
///   - Access Control: You must evaluate access modes (O_RDONLY, O_WRONLY, O_RDWR,
///     O_EXEC, O_SEARCH) present in fi->flags to ensure the calling process has permission.
///     Exception: If the mount option "-o default_permissions" is passed to FUSE, the kernel VFS
///     pre-validates standard POSIX permissions, and you may safely skip manual access checks.
///   - Writeback Caching (Enabled): The kernel may optimize writes and issue standalone read
///     requests even on file descriptors explicitly opened with O_WRONLY. Your .read callback
///     must be prepared to accommodate this.
///   - Writeback Caching (Disabled): The kernel relies on your filesystem to honor append-only
///     semantics. You must manually inspect fi->flags for O_APPEND and force all incoming .write
///     offsets to the true end-of-file boundary.
///   - Append Ambiguity: When writeback caching is enabled, the kernel natively handles O_APPEND.
///     However, if external components outside the kernel modify the underlying storage data, cache
///     desynchronization will occur. You should either ignore O_APPEND (letting the kernel handle it)
///     or return an error (-c.ENOTSUPP) indicating reliable appending is unavailable.
///
/// Advanced State and Optimization Controls:
///   - fi.fh (File Handle): You may assign a unique numeric index, pointer, or database descriptor
///     to this u64 field. FUSE guarantees this identical token will be passed to all downstream operations
///     (.read, .write, .flush, .release, .fsync) for this descriptor, enabling O(1) file lookups.
///     If your filesystem is completely stateless, you can leave fi.fh untouched at 0.
///   - Performance Flags: You can modify performance behaviors inline by adjusting fields inside fi:
///       * Set fi.direct_io = 1 to bypass the Linux Page Cache entirely (forcing synchronous I/O).
///       * Set fi.keep_cache = 1 to prevent the kernel from invalidating existing page caches for this
///         file upon open (crucial for performance if the file hasn't changed on the host backend).
///   - Kernel Shortcut Optimization: If you return -c.ENOSYS and the connection capability
///     FUSE_CAP_NO_OPEN_SUPPORT is enabled inside the initialization handshake (fuse_conn_info), the
///     kernel treats the open as a permanent success. Future open() requests for any file path will be
///     handled silently by the kernel without ever executing this userspace function again.
///
/// Parameters:
///   - fi: A mutable pointer to the FUSE file information structure containing VFS flags and out-parameters.
///
/// Returns:
///   - 0 on successful open negotiation.
///   - A negative C error code (e.g., -c.EACCES for permission denied, -c.ENOENT if missing, or
///     -c.ENOSYS for kernel optimization fallback).
fn open(path: [*:0]const u8, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Read data from an open file descriptor.
///
/// This operation fetches contents from a specific byte offset within a file. It acts as
/// the backing mechanism when applications invoke read(), pread(), or stream data.
///
/// Implementation Mechanics & Rules:
///   - Exact Return Value: Your implementation should return exactly the number of bytes
///     requested by the size parameter, except when encountering the End Of File (EOF) or
///     an explicit error.
///   - Zero Padding Padding: If you return fewer bytes than requested on a standard mount,
///     libfuse and the kernel will automatically pad the remaining unread buffer space with zeroes.
///   - Direct I/O Exception: If the filesystem was mounted with the "direct_io" option, the
///     kernel bypasses page caches. The exact return value of this function is passed straight
///     back to the calling system call, meaning short reads will not be zero-padded.
///
/// Parameters:
///   - buf: Destination buffer pointer where the read bytes must be copied.
///   - size: The total number of bytes requested to be read into the buffer.
///   - offset: The exact byte position inside the file from which to begin reading.
///   - fi: Optional file info structure. If populated during open(), fi.fh can be used
///         for O(1) file descriptor lookups.
///
/// Returns:
///   - The actual number of bytes read on success (>= 0).
///   - A negative C error code (e.g., -c.EIO) on failure.
fn read(path: [*:0]const u8, buf: [*]u8, size: usize, offset: std.c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Write data to an open file descriptor.
///
/// This operation commits an array of bytes to a specific byte offset within a file. It backstops
/// application system calls like write(), pwrite(), or standard output redirects.
///
/// Implementation Mechanics & Rules:
///    - Exact Return Value: Your implementation must return exactly the number of bytes requested
///      by the size parameter unless an unrecoverable error occurs.
///    - Direct I/O Exception: If the filesystem was mounted with the "direct_io" option, short writes
///      are allowed, and the exact return value is mirrored directly to the application system call.
///    - Direct I/O Constraints: When `fi.direct_io = 1` is engaged (or the application passes `O_DIRECT`),
///      the kernel forwards userspace memory pointers directly to your callback. Your implementation
///      must account for strict physical block/sector alignment rules. If the user payload, starting `offset`,
///      or incoming `size` fails to align with the underlying storage architecture limits (e.g., 512-byte
///      or 4096-byte boundaries), you must ensure your backend handles unaligned storage operations safely
///      to avoid memory corruption or performance degradation.
///    - Privilege Management: Unless the FUSE_CAP_HANDLE_KILLPRIV capability is explicitly disabled
///      during connection initialization, a successful write operation is expected to automatically
///      reset/clear the setuid and setgid permission bits on the file for security.
///
/// Parameters:
///    - buf: Source buffer containing the data payload that needs to be written.
///    - size: The total number of bytes from the buffer that must be written.
///    - offset: The exact byte position inside the file where the write payload should begin.
///    - fi: Optional file info structure. If populated during open(), fi.fh can be used
///      for O(1) file descriptor lookups.
///
/// Returns:
///    - The actual number of bytes written on success (>= 0).
///    - A negative C error code (e.g., -c.ENOSPC on disk full, -c.EIO) on failure.
fn write(path: [*:0]const u8, buf: [*]const u8, size: usize, offset: std.c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Get file system storage statistics.
///
/// This operation populates capacity and usage attributes for the filesystem mount, serving
/// as the backing callback for the POSIX statvfs() system call (e.g., used by df commands).
///
/// Implementation Mechanics & Rules:
///   - Ignored Fields: The Linux virtual file system layer and libfuse will entirely ignore the
///     f_favail, f_fsid, and f_flag fields that you set inside the statvfs struct. You only need
///     to focus on fields like block sizes, total blocks, and free blocks.
///
/// Parameters:
///   - stbuf: Target statvfs structure to populate with allocation metrics. Must be zeroed out first.
///
/// Returns:
///   - 0 on successful population of storage metrics.
///   - A negative C error code (e.g., -c.EIO) on failure.
fn statfs(path: [*:0]const u8, stbuf: *c.struct_statvfs) callconv(.c) c_int {}

/// Flushes cached data back to the storage backend before closing a file descriptor.
///
/// This callback is triggered during every single close() system call on a file descriptor.
/// It acts as a middle-ground interceptor allowing filesystems to push dirty data and
/// report I/O errors prior to full release.
///
/// Implementation Mechanics & Rules:
///   - Not fsync: This operation is absolutely not equivalent to an fsync() request. It is
///     not a definitive command to force synchronous physical disk writes, but rather an
///     opportunity to flush intermediate buffers.
///   - Close vs Release: Flush is called on *every* file descriptor close. In contrast,
///     the .release callback is only called once when the *last* duplicate file descriptor
///     referencing the open file is closed.
///   - Error Reporting: Under Linux, any negative C error code returned by this function
///     is propagated up and returned as the result of the application's close() call.
///     This makes it an excellent place to commit write-back cache data. However, you
///     cannot assume errors will be noticed, as many applications ignore close() return values,
///     and non-Linux systems may discard flush errors entirely.
///   - Multiple Invocations: Due to system calls like dup(), dup2(), or process fork() clones,
///     a single open() session can spawn multiple duplicate file descriptors. Consequently,
///     flush() can be called multiple times for one open file handle.
///   - Indeterminism: It is mathematically impossible to know if a given flush call is the
///     final one for a file handle. Every flush call must be treated with equal weight.
///     Do not assume flush will occur at a specific sequence point; it can be called more
///     times than anticipated, or occasionally skipped by the kernel.
///
/// Parameters:
///   - fi: Pointer to the file information structure. fi.fh can be used to track the open state.
///
/// Returns:
///   - 0 on success.
///   - A negative C error code (e.g., -c.EIO) if a cache write-back fails.
fn flush(path: [*:0]const u8, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Closes the final reference to an open file and releases resources.
///
/// This callback is triggered only when there are absolutely no more references remaining
/// to an open file handle across the entire system. This means all duplicate file descriptors
/// (created via dup or fork) have been closed, and all memory-mapped regions (mmap) are unmapped.
///
/// Implementation Mechanics & Rules:
///   - Exact Pairing: For every successful open() call made to your filesystem, FUSE guarantees
///     there will be exactly one corresponding release() call with the matching flags and fi.fh token.
///   - Finality: If a file path is opened multiple separate times, each session gets its own
///     release pairing. Only the final release call guarantees that no more incoming read or
///     write operations will hit that specific file handle instance.
///   - Ignored Return: The operating system completely ignores the return value of release.
///     Any error returned here will not be propagated back to the application closing the file,
///     so all resource cleanup must be finalized regardless of intermediate errors.
///
/// Parameters:
///   - fi: Pointer to the file information structure. Use fi.fh to safely deallocate or
///     free custom context/descriptors tracking this file.
///
/// Returns:
///   - 0 on success (any error code returned is silently discarded by the kernel).
fn release(path: [*:0]const u8, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Synchronizes file contents and dirty blocks directly to the underlying physical storage media.
///
/// This operation forces a physical commit of modified file blocks, serving as the backing mechanism
/// when applications call fsync() or fdatasync().
///
/// Implementation Mechanics & Rules:
///    - Data vs Metadata Sync: The datasync flag dictates what must be committed to disk. If datasync
///      is non-zero, you only need to flush modified user data blocks. You may completely skip flushing
///      updated file metadata blocks (such as mtime, ctime, or size changes) unless they are strictly
///      required to safely read the newly written data blocks. If datasync is zero, both data and
///      metadata must be fully committed.
///    - Kernel Fallback Optimization: If your filesystem does not implement this callback, FUSE will
///      automatically respond to the VFS layer with `-c.ENOSYS`. The Linux kernel catches this error
///      internally and safely masks it as a successful no-op, rather than propagating an error back
///      to the calling application. Implement this only if your storage backend supports physical commits.
///
/// Parameters:
///    - datasync: A conditional flag where non-zero indicates data-only synchronization (fdatasync behavior).
///    - fi: Optional file info structure. If populated during open(), fi.fh can be used
///      for O(1) file descriptor lookups.
///
/// Returns:
///    - 0 on successful physical synchronization.
///    - A negative C error code (e.g., -c.EIO) if the physical write-back fails.
fn fsync(path: [*:0]const u8, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Set an extended attribute (xattr) on a filesystem node.
///
/// This operation associates a key-value metadata pair with a specific path, backing system
/// calls like setxattr() and lsetxattr().
///
/// Implementation Mechanics & Rules:
///   - Flags Behavior: The flags parameter controls creation semantics. If flags is set to
///     c.XATTR_CREATE, the operation must fail and return -c.EEXIST if the attribute already
///     exists. If flags is set to c.XATTR_REPLACE, the operation must fail and return
///     -c.ENODATA if the attribute does not exist. A flags value of 0 allows either creation
///     or replacement.
///
/// Parameters:
///   - name: A null-terminated C-string representing the specific attribute key (e.g., "user.mime_type").
///   - value: A pointer to the raw byte buffer containing the attribute value data.
///   - size: The total size in bytes of the incoming value buffer.
///   - flags: Modifier flags determining creation rules (0, c.XATTR_CREATE, or c.XATTR_REPLACE).
///
/// Returns:
///   - 0 on successful attribute assignment.
///   - A negative C error code (e.g., -c.ENOTSUP if xattrs are disabled, -c.EEXIST, or -c.ENODATA).
fn setxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]const u8, size: usize, flags: c_int) callconv(.c) c_int {}

/// Get the value of an extended attribute (xattr) on a filesystem node.
///
/// This operation retrieves the byte payload associated with a specific attribute key, backing
/// system calls like getxattr() and lgetxattr().
///
/// Implementation Mechanics & Rules:
///   - Size Inquiry Shortcut: If the size parameter is passed as 0, the application is querying the
///     exact buffer capacity needed to store the value. In this specific scenario, you must skip
///     copying data to the buffer and immediately return the total size of the attribute value in bytes
///     without modifying the buffer.
///   - Buffer Constraints: If size is non-zero and the attribute value is too large to fit within
///     the provided capacity, you must fail the operation and return -c.ERANGE.
///
/// Parameters:
///   - name: A null-terminated C-string representing the target attribute key to retrieve.
///   - buf: Destination buffer pointer where the attribute value bytes must be copied.
///   - size: The maximum capacity of the destination buffer in bytes.
///
/// Returns:
///   - The size of the attribute value in bytes on success (>= 0).
///   - A negative C error code (e.g., -c.ENODATA if the key is missing, -c.ERANGE if buf is too small).
fn getxattr(path: [*:0]const u8, name: [*:0]const u8, buf: [*]u8, size: usize) callconv(.c) c_int {}

/// List the names of all extended attributes (xattrs) associated with a filesystem node.
///
/// This operation gathers all active attribute keys into a single buffer, backing system calls
/// like listxattr() and llistxattr().
///
/// Implementation Mechanics & Rules:
///   - Serialization Format: The output buffer must be populated with all attribute names encoded
///     as a sequence of consecutive, null-terminated C-strings (e.g., "user.a\0user.b\0"). The total
///     return value must reflect the aggregated length of this list including all internal null terminators.
///   - Size Inquiry Shortcut: If the size parameter is passed as 0, you must calculate and return
///     the total buffer size required to fit the entire list of names, without copying any data.
///   - Buffer Constraints: If size is non-zero and the serialized list exceeds the provided buffer
///     capacity, you must abort the copy and return -c.ERANGE.
///
/// Parameters:
///   - list: Destination buffer pointer where the sequence of null-terminated strings must be written.
///   - size: The maximum capacity of the destination buffer in bytes.
///
/// Returns:
///   - The total number of bytes written or required for the list on success (>= 0).
///   - A negative C error code (e.g., -c.ERANGE if the list exceeds capacity).
fn listxattr(path: [*:0]const u8, list: [*]u8, size: usize) callconv(.c) c_int {}

/// Remove an extended attribute (xattr) from a filesystem node.
///
/// This operation detaches a metadata key-value pair from a specific path, backing system
/// calls like removexattr() and lremovexattr().
///
/// Parameters:
///   - name: A null-terminated C-string representing the target attribute key to delete.
///
/// Returns:
///   - 0 on successful attribute removal.
///   - A negative C error code (e.g., -c.ENODATA if the attribute key does not exist).
fn removexattr(path: [*:0]const u8, name: [*:0]const u8) callconv(.c) c_int {}

/// Opens a directory for listing its contents and initializes state handles.
///
/// This callback validates access permissions when an application opens a directory stream,
/// backing operations like opendir().
///
/// Implementation Mechanics & Rules:
///   - Access Control: You must check if read/execute permissions allow opening this directory.
///     Exception: If the mount option "-o default_permissions" is passed to FUSE, the kernel
///     performs standard POSIX permission checks beforehand, and you can skip manual verification.
///   - State Management (fi.fh): You can optionally store an allocated state identifier,
///     pointer, or stream context in the fi.fh field. FUSE will reliably pass this identical token
///     to downstream directory operations (.readdir, .releasedir, and .fsyncdir) for this session.
///     If your directory tracking is completely stateless, you can leave fi.fh untouched at 0.
///
/// Parameters:
///   - fi: A mutable pointer to the FUSE file information structure containing VFS flags and out-parameters.
///
/// Returns:
///   - 0 on successful directory open negotiation.
///   - A negative C error code (e.g., -c.EACCES for permission denied, -c.ENOENT if missing).
fn opendir(path: [*:0]const u8, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Reads directory entries and feeds them to the kernel stream.
///
/// This callback lists contents of a directory node. It operates in one of two distinct strategies
/// negotiated via the filler function, backing system calls like getdents() or readdir().
///
/// Implementation Mechanics & Rules:
///    - Stateless Mode (Mode 1): Your implementation entirely ignores the incoming offset parameter.
///      When invoking the filler function, you always pass 0 as the offset argument. The filler function
///      will buffer entries continuously and never return 1 unless a critical out-of-memory or system error
///      occurs, allowing the entire directory contents to be read in one operation.
///    - Stateful/Offset Mode (Mode 2): Your implementation explicitly tracks and maps steady numeric offsets
///      for each directory entry. You evaluate the incoming offset parameter to pick up where a previous
///      invocation left off, and you must pass a valid, non-zero offset to the filler function for each item.
///      If the kernel's internal page buffer fills up completely, the filler function will return 1. In this
///      event, you must immediately halt processing, save your position, and return 0.
///    - Standard readdir (FUSE_READDIR_PLUS Absent): When the `FUSE_READDIR_PLUS` optimization flag is absent
///      from the incoming `flags`, the kernel ignores almost all fields inside the `stat` struct passed to the
///      filler. It exclusively reads the file type bitmask encoded within `stat->st_mode`. If
///      `fuse_config->use_ino` is enabled, it also parses `stat->st_ino`. All other statistical blocks are discarded.
///    - Optimized readdir (FUSE_READDIR_PLUS Present): When `flags` contains `c.FUSE_READDIR_PLUS`, the kernel
///      actively expects and validates a structurally complete, fully accurate `stat` block inside the filler.
///      The VFS layer grabs this metadata to eagerly populate its directory entry (dentry) cache. Providing
///      uninitialized, corrupted, or zeroed `stat` blocks during a `READDIR_PLUS` run will pollute the kernel
///      cache and corrupt subsequent standalone `getattr` queries for those child objects.
///
/// Parameters:
///    - buf: An opaque kernel buffer handle that must be forwarded directly into the filler callback.
///    - filler: The kernel-provided injector function pointer utilized to register file/directory entries.
///    - offset: The entry bookmark from which to resume listing (in Mode 2).
///    - fi: Optional file info structure. If populated during opendir(), fi.fh can track open state.
///    - flags: Operation modifiers containing configuration options (e.g., c.enum_fuse_readdir_flags).
///
/// Returns:
///    - 0 on a successful reading sequence.
///    - A negative C error code (e.g., -c.ENOENT, -c.EIO) on failure.
fn readdir(
    path: [*:0]const u8,
    buf: ?*anyopaque,
    filler: c.fuse_fill_dir_t,
    offset: std.c.off_t,
    fi: ?*c.struct_fuse_file_info,
    flags: c.enum_fuse_readdir_flags,
) callconv(.c) c_int {}

/// Closes the reference to an open directory and frees associated resources.
///
/// This callback is triggered when the kernel closes a directory stream handle, pairing
/// exactly with a prior successful opendir() invocation.
///
/// Implementation Mechanics & Rules:
///   - Null Path Safety: If the directory node was unlinked or removed from the filesystem
///     tree by another process after opendir() was called but before this release occurs,
///     the incoming path parameter will be null. You must safe-guard your logic and rely
///     primarily on the state stored inside fi.fh for resource cleanup.
///   - Return Interception: Similar to the standard file release operation, the return
///     value of this function is completely ignored by the kernel.
///
/// Parameters:
///   - path: The absolute path of the directory, or null if it was deleted mid-session.
///   - fi: Pointer to the file information structure. Use fi.fh to safely deallocate or
///     free custom context/descriptors tracking this directory stream.
///
/// Returns:
///   - 0 on success (any error code returned is silently discarded by the kernel).
fn releasedir(path: ?[*:0]const u8, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Synchronizes the contents and structure of a directory directly to physical storage.
///
/// This operation forces a physical commit of modified directory blocks, serving as the
/// backing mechanism when applications invoke fsync() directly on a directory descriptor.
///
/// Implementation Mechanics & Rules:
///    - Null Path Safety: If the directory was unlinked or deleted from the active directory tree
///      after it was initially opened but before an explicit sync is requested, the path parameter
///      passed by the kernel will be null. You must utilize `fi.fh` to locate the structural node.
///    - Data vs Metadata Sync: The datasync flag dictates what must be committed to disk. If datasync
///      is non-zero, you only need to flush the primary directory entry mapping payload data blocks.
///      You can safely omit updating metadata changes (such as timestamps or ownership modifications)
///      unless those blocks are required to consistently read the directory entries.
///    - Kernel Fallback Optimization: Mirroring the behavior of file-level `fsync`, if this callback
///      is left unimplemented, FUSE returns `-c.ENOSYS` to the VFS layer. The Linux kernel absorbs this
///      transparently, reporting a successful flush to the application descriptor rather than an error.
///
/// Parameters:
///    - path: The absolute path of the directory, or null if it was deleted mid-session.
///    - datasync: A conditional flag where non-zero indicates entry-data-only synchronization.
///    - fi: Optional file info structure. If populated during opendir(), fi.fh can be used
///      for O(1) directory tracking lookups.
///
/// Returns:
///    - 0 on successful physical synchronization.
///    - A negative C error code (e.g., -c.EIO) if the physical write-back fails.
fn fsyncdir(path: ?[*:0]const u8, datasync: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Initializes the filesystem state and negotiates features with the kernel.
///
/// This callback is executed exactly once by the FUSE runtime layer during mount startup,
/// before any other file operations are invoked. It allows the filesystem to configure
/// caching behaviors and exchange custom state pointers.
///
/// Implementation Mechanics & Rules:
///   - Private State Binding: The generic pointer (*anyopaque) returned by this function
///     is automatically stored by FUSE. It will be injected into the `private_data` field
///     of the global `fuse_context` struct across all future file operation calls, and
///     passed directly into the .destroy callback. This return value overrides whatever
///     initial pointer was supplied to fuse_main() or fuse_new().
///   - Capability Negotiation: The `conn` pointer permits checking and enabling kernel-level
///     capabilities (like writeback cache, splice, or async I/O profiles).
///   - Parameter Tuning: The `cfg` pointer exposes direct modification knobs for userspace
///     FUSE configs (e.g., forcing direct I/O, setting entry timeouts, or overriding default
///     permission checks).
///
/// Parameters:
///   - conn: Read-write structure tracking features supported and requested by the kernel VFS.
///   - cfg: Core configuration rules that modify overall FUSE tracking and runtime characteristics.
///
/// Returns:
///   - A pointer to your custom application/filesystem context state, or null.
fn init(conn: *c.struct_fuse_conn_info, cfg: *c.struct_fuse_config) callconv(.c) ?*anyopaque {}

/// Cleans up filesystem state and frees persistent memory maps upon exit.
///
/// This callback is executed exactly once during unmounting or filesystem termination,
/// guaranteeing a teardown sequence after all active sessions have ceased.
///
/// Implementation Mechanics & Rules:
///   - Context Reclamation: The incoming parameter is the exact pointer returned by your
///     prior .init callback call. This is the final opportunity to safely free backing databases,
///     unmap memory, close storage descriptors, or free nested struct structures.
///
/// Parameters:
///   - private_data: The custom context state pointer originally instantiated within .init.
fn destroy(private_data: ?*anyopaque) callconv(.c) void {}

/// Check file access permissions for a specific user or group context.
///
/// This callback handles verification requests generated by the access() or faccessat()
/// system calls, checking read, write, or execute accessibility.
///
/// Implementation Mechanics & Rules:
///   - Bypass Option: If the "-o default_permissions" mount option is passed to FUSE, the
///     kernel handles all permission checks natively using standard POSIX ACLs. In this
///     case, this callback will never be executed by the kernel.
///   - Evaluation Mode: The incoming integer mask represents the access bit flags to test,
///     specifically c.F_OK (test file existence), or a bitwise combination of c.R_OK,
///     c.W_OK, and c.X_OK (read, write, execute permissions respectively).
///   - Kernel Legacy: This method is entirely uncalled and ignored under ancient Linux
///     kernel versions 2.4.x.
///
/// Parameters:
///   - mask: Bitmask of permission attributes to evaluate (e.g., F_OK, R_OK, W_OK, X_OK).
///
/// Returns:
///   - 0 if the requested access levels are permitted.
///   - A negative C error code (e.g., -c.EACCES for permission denied, -c.ENOENT if missing).
fn access(path: [*:0]const u8, mask: c_int) callconv(.c) c_int {}

/// Atomically create and open a file in a single sequence operation.
///
/// This optimized callback handles application calls that create a regular file and immediately
/// request a file descriptor (e.g., open() with O_CREAT).
///
/// Implementation Mechanics & Rules:
///   - Fallback Logic: If your filesystem does not implement this .create callback, or if it runs
///     on a legacy Linux kernel prior to version 2.6.15, FUSE seamlessly falls back to a
///     two-step process: it first calls your .mknod callback to generate the node, followed
///     by your .open callback to set up the file descriptor.
///   - Creation Semantics: If the target path does not exist, you must instantiate it as a regular
///     file utilizing the requested mode bits, and then initialize the state variables inside `fi`.
///   - State Management (fi.fh): Just like standard open(), you can populate fi.fh with a
///     custom pointer or reference handle to speed up subsequent read/write tracking.
///
/// Parameters:
///   - mode: The permission bits to assign to the new file if creation is triggered.
///   - fi: A mutable pointer to the FUSE file information structure containing VFS flags and out-parameters.
///
/// Returns:
///   - 0 on successful creation and open negotiation.
///   - A negative C error code (e.g., -c.EEXIST if O_EXCL was violated, -c.ENOSPC on disk full).
fn create(path: [*:0]const u8, mode: c.mode_t, fi: *c.struct_fuse_file_info) callconv(.c) c_int {}

/// Perform POSIX file locking operations.
///
/// This callback manages advisory byte-range file locks, processing commands triggered
/// by application calls to fcntl() or lockf().
///
/// Implementation Mechanics & Rules:
///   - Command Actions: The cmd parameter specifies the locking action:
///       * c.F_GETLK: Query if a conflicting lock exists. If one is found, you must populate
///         the flock structure with its details.
///       * c.F_SETLK: Acquire or release a lock non-blockingly. Fail with -c.EACCES or -c.EAGAIN
///         if a conflicting lock is held by another process.
///       * c.F_SETLKW: Acquire a lock blockingly (wait until the lock becomes available).
///   - Whence Simplification: The kernel guarantees that the lock->l_whence field is always
///     normalized to c.SEEK_SET (absolute byte offsets relative to the start of the file)
///     before this callback runs.
///   - Lock Ownership: You must identify the unique owner of a lock session using the
///     fi->owner field (a u64 identifier unique to the locking process). Standard POSIX PIDs
///     are not sufficient on their own due to file descriptor sharing across threads or forks.
///   - Get Lock (F_GETLK) Optimization: FUSE automatically checks local locks first. If a
///     conflicting local lock exists, FUSE populates flock->l_pid and returns immediately
///     without running this function. If no local conflict exists, this callback runs to check
///     remote cluster/network states. You may optionally populate flock->l_pid with a cluster-wide
///     PID or leave it at 0.
///   - Set Lock (F_SETLK/W) PIDs: For acquisition and release commands, the flock->l_pid
///     field is pre-populated by the kernel with the local PID of the process requesting the lock.
///   - Fallback behavior: If this method is left unimplemented, the Linux kernel manages file
///     locking locally inside the page cache. Implementing this callback is generally only
///     necessary for network, distributed, or clustered filesystems.
///
/// Parameters:
///   - fi: Pointer to the file information structure. Inspect fi.owner to verify lock ownership.
///   - cmd: The fcntl lock command flag (c.F_GETLK, c.F_SETLK, or c.F_SETLKW).
///   - lock: Mutable pointer to the POSIX flock structural boundaries and type attributes.
///
/// Returns:
///   - 0 on a successful locking operation.
///   - A negative C error code (e.g., -c.EAGAIN for locked resource, -c.EINTR if blocked SETLKW is interrupted).
fn lock(path: [*:0]const u8, fi: *c.struct_fuse_file_info, cmd: c_int, flock: *c.struct_flock) callconv(.c) c_int {}

/// Change the access and modification times of a file with nanosecond resolution.
///
/// This operation supersedes legacy utime methods, providing direct alignment with modern
/// system calls like utimensat() and futimens().
///
/// Implementation Mechanics & Rules:
///   - Array Formats: The tv array parameter contains exactly two elements:
///       * tv[0] specifies the new Access Time (atime).
///       * tv[1] specifies the new Modification Time (mtime).
///   - Special Timestamp Flags: The tv[x].tv_nsec field can carry special UAPI magic flags:
///       * c.UTIME_NOW: The time must be updated to the current system time atomically.
///       * c.UTIME_OMIT: The specific timestamp must be left entirely unchanged.
///   - Open File Optimization: The fi pointer is guaranteed to be null if the target file is
///     not currently open. However, it can also be null even if the file is open depending on VFS
///     state, so your logic must gracefully fall back to path-based lookups when fi is absent.
///
/// Parameters:
///   - tv: A pointer to an array of two timespec structures outlining target atime and mtime.
///   - fi: Optional file info structure. If populated during open(), fi.fh can bypass path lookups.
///
/// Returns:
///   - 0 on successful timestamp updates.
///   - A negative C error code (e.g., -c.EACCES for permission issues, -c.EROFS for read-only systems).
fn utimens(path: [*:0]const u8, tv: *const [2]c.struct_timespec, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {}

/// Map a logical file block index to a physical disk device block index.
///
/// This callback maps data layouts on storage blocks, serving as the backing function
/// for the FIBMAP ioctl operation.
///
/// Implementation Mechanics & Rules:
///   - Environmental Constraints: This method is functionally valid and invoked only for raw
///     block-device-backed filesystems mounted explicitly with the "blkdev" FUSE configuration option.
///   - In-Out Mapping: The idx parameter acts as both an input and an output variable. On entry,
///     *idx contains the logical block index inside the file scope (calculated relative to the blocksize).
///     Before returning, your implementation must overwrite *idx with the true physical block offset
///     address pointing directly onto the underlying physical block device storage media.
///
/// Parameters:
///   - blocksize: The size of individual blocks in bytes (e.g., 512 or 4096).
///   - idx: A mutable pointer to the block counter value tracking logical input and physical output.
///
/// Returns:
///   - 0 on successful address translation mapping.
///   - A negative C error code (e.g., -c.ENOSYS if unsupported, -c.EINVAL).
fn bmap(path: [*:0]const u8, blocksize: usize, idx: *u64) callconv(.c) c_int {}

/// Perform an ioctl (input/output control) operation on a file or directory.
///
/// This callback handles device-specific or filesystem-specific control commands, backing
/// the ioctl() system call. It facilitates out-of-band communication loops between applications
/// and the filesystem driver.
///
/// Implementation Mechanics & Rules:
///   - Argument Truncation: The "unsigned long" request code submitted by the userspace application
///     is automatically truncated down to a 32-bit unsigned integer by the FUSE kernel layer before
///     being passed to the cmd parameter.
///   - Data Buffering Decoding: The data layout structure, transfer direction, and memory size are
///     extracted by decoding the cmd parameter using standard POSIX _IOC_* macro rules:
///       * If the command evaluates to _IOC_NONE, the data pointer will be null.
///       * If the command evaluates to _IOC_WRITE, data holds incoming payload blocks from userspace.
///       * If the command evaluates to _IOC_READ, data marks an outbound allocation space to fill.
///       * If both read and write bits are set, data acts as a bidirectional in/out memory segment.
///       * For all non-null scenarios, the memory window spans exactly _IOC_SIZE(cmd) bytes.
///   - Compatibility Layer: If the flags parameter contains the FUSE_IOCTL_COMPAT bitmask, it indicates
///     a 32-bit ioctl execution layer originates from a 32-bit application running inside a 64-bit
///     kernel environment. You must adjust structure padding offsets accordingly.
///   - Node Discrimination: If the flags parameter contains the FUSE_IOCTL_DIR bitmask, the operation
///     is targeting a directory handle rather than a regular file, meaning the fi parameter refers to
///     a directory descriptor opened by .opendir.
///
/// Parameters:
///   - cmd: The 32-bit truncated ioctl operation command code identifier.
///   - arg: The raw untranslated pointer argument passed directly by the application system call.
///   - fi: Optional file info structure. Inspect flags to determine if it tracks a file or directory.
///   - flags: Contextual bitmask states (e.g., FUSE_IOCTL_COMPAT, FUSE_IOCTL_DIR).
///   - data: The kernel-mapped staging buffer for payload transfers matching _IOC_SIZE(cmd).
///
/// Returns:
///   - 0 or a positive value on successful command completion.
///   - A negative C error code (e.g., -c.ENOTTY if the command is unrecognized or unsupported).
const ioctl = (if (fuse_version < 35) struct {
    fn ioctl(
        path: [*:0]const u8,
        cmd: c_int,
        arg: ?*anyopaque,
        fi: ?*c.struct_fuse_file_info,
        flags: c_uint,
        data: ?*anyopaque,
    ) callconv(.c) c_int {}
} else struct {
    fn ioctl(
        path: [*:0]const u8,
        cmd: c_uint,
        arg: ?*anyopaque,
        fi: ?*c.struct_fuse_file_info,
        flags: c_uint,
        data: ?*anyopaque,
    ) callconv(.c) c_int {}
}).ioctl;

/// Poll a file descriptor for I/O readiness events.
///
/// This callback checks if a file descriptor is ready for non-blocking read or write operations,
/// backing asynchronous polling mechanisms like poll(), select(), or epoll().
///
/// Implementation Mechanics & Rules:
///   - Async Notification (ph): If the ph parameter is non-null, the filesystem driver must
///     register this poll handle. When the underlying file resource later becomes ready for I/O,
///     you must notify the kernel by calling fuse_notify_poll() using this specific handle.
///   - Notification Coalescing: A single notification call to fuse_notify_poll() is completely
///     sufficient to clear all outstanding poll registrations, no matter how many times poll()
///     was invoked with a non-null ph. Extra notifications are harmless to functional correctness,
///     but they introduce unnecessary performance overhead.
///   - Memory Ownership: The filesystem is fully responsible for managing the lifetime of the
///     fuse_pollhandle structure. You must explicitly free it by calling fuse_pollhandle_destroy()
///     once it is no longer in use or after notification has been dispatched.
///   - Return Events: Your implementation must assign the active readiness status flags (e.g.,
///     POLLIN, POLLOUT, POLLERR) to the memory location pointed to by reventsp.
///
/// Parameters:
///   - fi: Optional file info structure. If populated during open(), fi.fh can track open state.
///   - ph: An optional pointer to a FUSE poll handle structure used for asynchronous wakeups.
///   - reventsp: A mutable pointer to an unsigned integer where active output events must be assigned.
///
/// Returns:
///   - 0 on successful poll state evaluation.
///   - A negative C error code (e.g., -c.EIO) on failure.
fn poll(
    path: [*:0]const u8,
    fi: ?*c.struct_fuse_file_info,
    ph: ?*c.struct_fuse_pollhandle,
    reventsp: *c_uint,
) callconv(.c) c_int {}

/// Write contents of a generic buffer vector to an open file.
///
/// This optimized zero-copy capable operation commits data from a structured buffer vector
/// to a specific offset inside a file, backing system calls like writev() or splice().
///
/// Implementation Mechanics & Rules:
///    - Data Transfer: Unlike the standard .write callback which receives a raw byte array, this
///      method receives data encapsulated inside a struct_fuse_bufvec wrapper. You should utilize
///      the built-in libfuse function fuse_buf_copy() to efficiently transfer data from this source
///      vector directly into your destination storage blocks.
///    - Direct I/O Constraints: When zero-copy pipe operations or `fi.direct_io = 1` are active,
///      the data chunks referenced by individual vector elements within `struct_fuse_bufvec` may map
///      directly back to physical kernel page segments. If handling raw, page-mapped memory, your
///      underlying driver logic must conform to physical device architecture sector restrictions
///      (typically 512 or 4096 bytes) for misaligned offsets or incomplete buffer frames.
///    - Privilege Management: Unless the FUSE_CAP_HANDLE_KILLPRIV capability is explicitly disabled
///      during connection initialization, a successful write operation is expected to automatically
///      reset/clear the setuid and setgid permission bits on the file for security.
///
/// Parameters:
///    - buf: A mutable pointer to the FUSE buffer vector tracking data chunks and memory/pipe flags.
///    - off: The exact byte position inside the file where the write payload should begin.
///    - fi: Optional file info structure. If populated during open(), fi.fh can track open state.
///
/// Returns:
///    - The actual number of bytes written on success (>= 0).
///    - A negative C error code (e.g., -c.ENOSPC on disk full, -c.EIO) on failure.
fn write_buf(
    path: [*:0]const u8,
    buf: *c.struct_fuse_bufvec,
    off: std.c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) c_int {}

/// Read data from an open file and return it within a generic buffer vector.
///
/// This optimized zero-copy operation fetches file data and wraps it inside a buffer vector structure.
/// It acts as the backing mechanism when applications leverage splice(), vmsplice(), or advanced
/// pipe-based zero-copy streaming reads.
///
/// Implementation Mechanics & Rules:
///   - Zero-Copy Allocation: Unlike standard .read, you do not copy data into a provided buffer.
///     Instead, you must dynamically allocate a `struct fuse_bufvec` using standard C allocation (e.g., malloc)
///     and assign it to the pointer-to-pointer container `bufp`.
///   - Descriptor Storing: To achieve complete zero-copy operations, you are not forced to copy file contents
///     into memory regions at all. Your implementation can simply assign the underlying backend system file
///     descriptor directly to the flags inside the `fuse_bufvec` structure, delegating actual data transfers
///     to later pipe operations.
///   - Memory Allocation Rules: If you choose to map explicit memory chunks inside the buffer vector rather
///     than passing a raw file descriptor, every memory region block must be individually allocated dynamically.
///     The downstream FUSE caller takes exclusive ownership of these allocations and will automatically free
///     both the primary `fuse_bufvec` memory block and any nested allocations once consumption completes.
///
/// Parameters:
///   - bufp: A mutable pointer-to-pointer target where the dynamically allocated buffer vector must be stored.
///   - size: The maximum total number of data bytes requested to be mapped or referenced.
///   - off: The exact byte position inside the file from which to begin reading data references.
///   - fi: Optional file info structure. If populated during open(), fi.fh can track open state.
///
/// Returns:
///   - 0 on successful buffer generation and assignment.
///   - A negative C error code (e.g., -c.ENOMEM on allocation exhaustion, -c.EIO) on failure.
fn read_buf(
    path: [*:0]const u8,
    bufp: *?*c.struct_fuse_bufvec,
    size: usize,
    off: std.c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) c_int {}

/// Perform BSD flock file locking operations on a file descriptor.
///
/// This callback manages advisory whole-file locks, processing commands triggered when userspace
/// applications invoke the flock() system call.
///
/// Implementation Mechanics & Rules:
///   - Operation Decoding: The op parameter dictates the specific locking state mutation:
///       * c.LOCK_SH: Request a shared lock (multiple processes can hold shared locks concurrently).
///       * c.LOCK_EX: Request an exclusive lock (only one process can hold an exclusive lock).
///       * c.LOCK_UN: Release an existing shared or exclusive lock state.
///   - Non-blocking Mode: If the incoming request is non-blocking, the kernel applies a bitwise OR
///     combining the target action with c.LOCK_NB (e.g., `op & c.LOCK_NB != 0`). If a lock conflict is
///     encountered during a non-blocking invocation, you must fail immediately and return -c.EWOULDBLOCK.
///   - Lock Ownership: FUSE sets `fi.owner` to a unique hash token tied directly to this open file handle
///     instance. FUSE guarantees that this exact matching identifier will be passed to your .release
///     callback when the file descriptor is finalized, letting you cleanly audit and purge forgotten locks.
///   - Fallback Behavior: If this method is left unimplemented, the Linux kernel manages BSD flock states
///     locally within the VFS layer. Implementing this callback is generally only required for clustered,
///     network, or distributed filesystems where multi-node state visibility matters.
///
/// Parameters:
///   - fi: Pointer to the file information structure. Inspect fi.owner to track unique session locks.
///   - op: The compound bitmask tracking lock action commands and non-blocking modifier states.
///
/// Returns:
///   - 0 on a successful locking state change.
///   - A negative C error code (e.g., -c.EWOULDBLOCK for resources busy, -c.EINTR if interrupted).
fn flock(path: [*:0]const u8, fi: *c.struct_fuse_file_info, op: c_int) callconv(.c) c_int {}

/// Pre-allocates space for an open file to guarantee block availability.
///
/// This callback ensures that storage blocks are allocated for a specified byte range of a file,
/// backing the fallocate() system call.
///
/// Implementation Mechanics & Rules:
///   - Space Guarantees: If this function successfully returns 0, any subsequent write operations
///     targeting the specified byte range are guaranteed not to fail due to physical out-of-space
///     errors (-c.ENOSPC) on the underlying filesystem media.
///   - Allocation Modes: The mode parameter (the second argument) dictates the allocation behavior:
///       * Mode 0 (Default): Allocates blocks and extends the file size if the range goes beyond EOF.
///       * c.FALLOC_FL_KEEP_SIZE: Allocates blocks but prevents the file's visible size attribute
///         from increasing, even if the allocated range exceeds the current end-of-file marker.
///       * c.FALLOC_FL_PUNCH_HOLE: Releases space/blocks in the specified range, turning it into a
///         sparse "hole". This must be bitwise-ORed with FALLOC_FL_KEEP_SIZE.
///
/// Parameters:
///   - mode: Operational flags controlling the allocation or deallocation strategy.
///   - offset: The starting byte position of the target allocation range.
///   - len: The length of the target allocation range in bytes.
///   - fi: Optional file info structure. If populated during open(), fi.fh can track open state.
///
/// Returns:
///   - 0 on successful space allocation.
///   - A negative C error code (e.g., -c.ENOSPC if out of room, -c.EOPNOTSUPP if mode is unsupported).
fn fallocate(
    path: [*:0]const u8,
    mode: c_int,
    offset: std.c.off_t,
    len: std.c.off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) c_int {}

/// Server-side copy optimization between two open file segments.
///
/// This callback performs an optimized in-kernel data transfer between a source file and a destination
/// file, backing the copy_file_range() system call. It eliminates the heavy performance penalty of
/// reading data out of FUSE into userspace via glibc buffers only to write it straight back in.
///
/// Implementation Mechanics & Rules:
///    - Fallback Protocol: If this operation is left unimplemented, FUSE returns an error like `-c.ENOSYS`,
///      forcing modern applications to fall back to standard, user-space read/write loops. Legacy
///      glibc automated fallback emulations have been removed, making manual fallback management mandatory.
///    - Cross-File Operations: The source (`fi_in`) and destination (`fi_out`) files can point to completely
///      different files or the same file (for overlapping/shifting operations).
///    - Cross-Filesystem Boundaries: Although source and destination files can differ, the Linux kernel
///      strictly enforces that both file descriptors must reside within the exact same mounted FUSE filesystem
///      instance. If an application attempts to bridge two separate FUSE mount points via this call, you
///      must immediately abort and return `-c.EXDEV`.
///    - Position Updating: Unlike read/write callbacks, this function takes absolute offsets (`offset_in`
///      and `offset_out`) instead of implicitly updating file descriptor position trackers.
///    - Flags Constraints: The flags parameter is currently reserved by the Linux kernel VFS layer for
///      future extensions and must be validated (typically expected to be 0).
///
/// Parameters:
///    - path_in: The path of the source file.
///    - fi_in: Mutable pointer to the source file info structure.
///    - offset_in: The starting byte offset inside the source file.
///    - path_out: The path of the destination file.
///    - fi_out: Mutable pointer to the destination file info structure.
///    - offset_out: The starting byte offset inside the destination file.
///    - size: The maximum number of bytes to copy between the descriptors.
///    - flags: Modifier flags reserved for kernel VFS expansion.
///
/// Returns:
///    - The number of bytes successfully copied on success (>= 0).
///    - A negative C error code (e.g., `-c.EXDEV` if cross-filesystem copying is restricted, `-c.EIO`).
fn copy_file_range(
    path_in: [*:0]const u8,
    fi_in: *c.struct_fuse_file_info,
    offset_in: std.c.off_t,
    path_out: [*:0]const u8,
    fi_out: *c.struct_fuse_file_info,
    offset_out: std.c.off_t,
    size: usize,
    flags: c_int,
) callconv(.c) isize {}

/// Find the next data segment or sparse hole after a specified offset.
///
/// This callback maps sparse file block regions, backing advanced lseek() mutations. It allows
/// applications to rapidly skip massive unallocated holes inside virtual or sparse storage files.
///
/// Implementation Mechanics & Rules:
///   - Sparse Seek Decoding: The whence parameter dictates the targeted lookup search pattern:
///       * c.SEEK_DATA: Advance the current offset to the start of the next consecutive block allocation
///         containing valid, non-zero data payload, starting from the off parameter. If off falls
///         directly inside data, it returns off. If no more data exists before EOF, fail with -c.ENXIO.
///       * c.SEEK_HOLE: Advance the current offset to the start of the next unallocated sparse hole or
///         virtual empty region. If off falls inside a hole, it returns off. If no more holes exist,
///         it returns the absolute file size boundary (EOF).
///
/// Parameters:
///   - off: The relative byte position inside the file from which to begin evaluating boundaries.
///   - whence: The location search modifier flag (exclusively c.SEEK_DATA or c.SEEK_HOLE).
///   - fi: Optional file info structure. If populated during open(), fi.fh can track open state.
///
/// Returns:
///   - The calculated absolute file offset address matching the target block search on success (>= 0).
///   - A negative C error code (e.g., -c.ENXIO if seeking past data boundaries, -c.EINVAL for invalid flags).
fn lseek(path: [*:0]const u8, off: std.c.off_t, whence: c_int, fi: ?*c.struct_fuse_file_info) callconv(.c) std.c.off_t {}

/// Get extended file attributes with precise bitmask selectivity.
///
/// This modern operation serves as the backing function for the Linux statx() system call,
/// replacing legacy stat and fstat implementations with a high-resolution, lightweight querying layer.
///
/// Implementation Mechanics & Rules:
///   - Mask Optimization: The mask parameter specifies the exact attributes requested by the application
///     (e.g., STATX_SIZE, STATX_MTIME). You only need to calculate and populate fields matching this mask.
///     Set `stxbuf.stx_mask` to indicate which fields were successfully provided.
///   - Pathless Resolution: If the path argument is null, the kernel guarantees the AT_EMPTY_PATH bit
///     is pre-set inside the flags parameter. You must resolve attributes directly using the file handle
///     provided inside `fi.fh`.
///   - Handle Resiliency: The fi pointer can be null even if a path is present, depending on how the
///     application invoked the query, requiring manual path lookup fallbacks.
///
/// Parameters:
///   - path: The target node path string, or null if resolving directly via an open descriptor.
///   - flags: Control flags altering standard resolution behaviors (e.g., AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH).
///   - mask: Bitmask defining the explicit subset of attributes requested by the calling process.
///   - stxbuf: The target statx structure to populate with high-resolution timestamps and metadata.
///   - fi: Optional file info structure. If populated during open(), fi.fh handles direct descriptors.
///
/// Returns:
///   - 0 on successful attribute structural population.
///   - A negative C error code (e.g., -c.ENOENT if missing, -c.EACCES for permission blocks).
fn statx(
    path: ?[*:0]const u8,
    flags: c_int,
    mask: c_uint,
    stxbuf: *c.struct_statx,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) c_int {}
