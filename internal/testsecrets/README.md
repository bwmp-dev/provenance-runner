# Job-private memory files

This Linux primitive prepares anonymous `memfd` files backed by shmem/tmpfs.
It is not yet wired to gateway delivery or sandbox preparation and does not
advertise test-secret support. Full acceptance still requires exact delivered
identity validation, redactor registration, non-root read-only sandbox mounts,
failure/cancellation teardown and restart reconciliation.

The entire name-ordered set is validated before allocation: at most 64 unique
safe names and 64 KiB aggregate nonempty UTF-8 values. Each inode is sealed
against writing, growing, shrinking and removal of seals. The descriptors are
close-on-exec and never backed by workspace files. The owner retains them until
sandbox and gofer teardown has completed, then closes them. Closing only the
owner's descriptors cannot revoke another process's already-open reference.

Files have read permissions suitable for the distinct non-root guest UID, but
no shared host-directory entry. Access to their `/proc/<owner>/fd/<n>` handles
is subject to the kernel's process-inspection permission checks. Those handles
are trusted composition inputs, not customer-selectable mounts. Mounts must also
be read-only, nosuid, nodev and noexec. Never weaken permissions on an existing
host directory or expose these handles to unrelated jobs.

The caller clears delivery buffers after redactor and file preparation.
The helper avoids ordinary diagnostic/JSON serialization of values. This does
not promise protection against the trusted host user, root, debuggers, swap,
crash dumps, or forensic recovery. Do not enable capability advertisement until
the complete sandbox lifecycle has passed its acceptance tests.
# Delivery validation (toolkit alpha.23)

`TakeDelivery` requires the complete selected reference set, exact request,
lease and attempt, bounded current expiry, UTF-8 values and the 64-KiB aggregate
limit. Unknown protobuf fields are refused. Success transfers owned buffers out
of the protobuf response; every rejected response clears all recognized values.
The caller must clear successful inputs after preparing files and redaction.

This is not stream integration or capability advertisement. The worker still
refuses secret-bearing offers, including configuration selections with omitted
references. Pending-request connection binding, accepted-lease sequencing,
redactor registration, real sandbox mounts and teardown remain required before
activation. The general transport message limit is unchanged.
