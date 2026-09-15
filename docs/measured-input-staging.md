# Descriptor-only measured input staging

The internal root-controller staging function accepts at most 256 flat aliases,
read-only regular local-file descriptors, exact sizes and SHA-256 digests. It
does not accept source paths, directory trees, archives, FIFOs, devices or sockets.
Names cannot select parent paths or hidden controller metadata. Total declared
bytes must fit the caller's admitted storage ceiling, capped at 64 GiB.

The destination must already be an empty root-owned 0700 directory on an allowed
local filesystem. All creates are exclusive and relative to its retained directory
descriptor. Copying uses a fixed buffer, checks cancellation between reads, refuses
extra or missing bytes, verifies the copied digest and checks source metadata
again. Completed files become root-owned read-only files; the directory is sealed
0555 only after all copies and syncs succeed. The enclosing job bundle must retain
private traversal permissions so other host identities cannot read job inputs.

A failure removes only files created by that invocation whose names still match
the retained inodes. It does not sweep existing contents. Unknown entries and an
already sealed directory are refused. Source descriptors remain caller-owned and
must not be closed concurrently. Disk I/O is finite in bytes, not a promise that
a failing host filesystem can always be interrupted immediately.

This is not a privileged RPC or a complete bundle lifecycle. The owning controller
must derive the ceiling and expected inventory from the admitted job, provide
global capacity reservations, journal bundle ownership and recover its files,
and keep the measured launch gate closed on any staging or cleanup error.

The real measured Sentry fixture rejects incorrect hashes/sizes, path aliases,
duplicate names, writable descriptors, pipes, insufficient aggregate allowance,
nonempty directories and attempts to reopen sealed inputs. Rejected partial copies
leave the private directory empty and pre-existing entries remain unchanged. After
successful staging the fixture changes the original source: the actual guest must
still read the original verified copy through its read-only input mount while all
storage-quota, packet-policy and journaled cleanup cases continue to pass.
