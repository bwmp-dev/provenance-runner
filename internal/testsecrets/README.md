# Job-private memory files

This Linux primitive prepares anonymous `memfd` files backed by shmem/tmpfs.
It is not yet wired to gateway delivery or the remote worker and does not
advertise test-secret support. Full acceptance still requires exact delivered
identity validation, redactor registration, non-root read-only sandbox mounts,
failure/cancellation teardown and restart reconciliation.

The entire name-ordered set is validated before allocation: at most 64 unique
safe names and 64 KiB aggregate nonempty UTF-8 values. Each inode is sealed
against writing, growing, shrinking and removal of seals. The descriptors are
close-on-exec and never backed by workspace files. The owner retains them until
sandbox and gofer teardown has completed, then closes them. Closing only the
owner's descriptors cannot revoke another process's already-open reference.

The sealed files are trusted composition inputs, not customer-selectable mounts.
They cannot be directly bind-mounted by the pinned runtime; non-root gofer access
to parent process descriptors is also restricted. The gVisor provider copies the
bounded set into an exclusively created job directory under a verified tmpfs
parent owned by the runner with mode 0700. Only that job's inner subtree is mounted
at `/run`, read-only, nosuid, nodev and noexec. No values enter bundle files or
the immutable image. The guest can read but cannot modify the files; other guest
sandboxes cannot reach the private host parent. No existing host permissions are
broadened. A missing or unsafe tmpfs refuses preparation rather than falling back
to persistent storage.

The tmpfs path is derived from the runner state-root identity and random container
ID, not supplied by a job. Ownership metadata is committed before creation. Normal
cleanup and startup reconciliation remove the exact job directory only after
runtime teardown; failed cleanup preserves the bundle for retry/quarantine.
This sandbox implementation does not yet establish the full gateway/worker
accepted-lease, expiry, reconnect or slot-quarantine lifecycle.

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
