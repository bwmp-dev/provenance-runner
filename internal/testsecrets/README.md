# Job-private memory files

This Linux primitive prepares anonymous `memfd` files backed by shmem/tmpfs.
Production defaults do not advertise test-secret support. The authenticated
worker composition requires the explicit `connect --enable-test-secrets`
operator switch and an explicitly supporting provider. This switch is never
accepted from connection/job JSON or enabled by installer defaults. It permits
controlled lifecycle acceptance without a patched binary; it does not enable
backend scheduling or supply key custody. Full composed acceptance and deployed key custody
remain prerequisites for enabling secret-bearing scheduling.

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
Sandbox tests alone do not establish the full gateway/worker lifecycle.

Trusted sandbox composition must supply `TestSecretExpiresAt` alongside the
sealed files. The provider refuses missing or expired delivery timestamps during
resolution, preparation, and immediately before launching the runtime. Expiry
does not close files underneath a running sandbox: teardown remains responsible
for removing the private tmpfs and closing handles after the runtime is gone.
The delivery timestamp is not accepted from job JSON or persisted in bundle
metadata. The worker requests the latest durable lease after slow preparation,
not the initial offered expiry.

Paper's trusted composition accepts an ephemeral `execution.TestSecretSource`
context callback. It invokes that callback only after all pinned downloads and
workspace materialization, immediately before sandbox preparation. Unsupported
sandboxes are refused without invoking the callback. Returned files must be
available and unexpired; failed acquisition or resolution closes caller-owned
handles. An explicitly supporting sandbox takes ownership on every Prepare path,
including partial failure. This hook does not itself authorize delivery: the
gateway reauthorizes the current accepted lease, and the runner binds the
response to a single pending request and original connection generation.

The caller clears delivery buffers after redactor and file preparation.
The helper avoids ordinary diagnostic/JSON serialization of values. This does
not promise protection against the trusted host user, root, debuggers, swap,
crash dumps, or forensic recovery. Only use the opt-in for a controlled acceptance
runner until the complete lifecycle and staged deployment gates have passed.
# Delivery validation (toolkit alpha.23)

`TakeDelivery` requires the complete selected reference set, exact request,
lease and attempt, bounded current expiry, UTF-8 values and the 64-KiB aggregate
limit. Unknown protobuf fields are refused. Success transfers owned buffers out
of the protobuf response; every rejected response clears all recognized values.
The caller must clear successful inputs after preparing files and redaction.

The default worker refuses secret-bearing offers and all delivery wire carriers.
The explicit operator opt-in additionally requires an explicitly supporting
worker. Enabled offers must exactly match configuration names and immutable
versions; duplicate JSON keys, omitted references and inaccessible composition
are refused. Only the delivery variant permits 98304 encoded bytes. The codec
refuses duplicate deliveries, oneof overrides and overwritten value fields
before decoding, and retains the 65536-byte bound for all other messages.

Delivery bypasses ordinary replay hashing and is never journaled. Owned buffers
are cleared after sealing and on refusal, receive failure and cancellation.
Pending requests expire after at most 15 seconds and cannot cross a connection
generation. Request IDs also include fresh cryptographic randomness, so resetting
in-memory generation/sequence counters on process restart cannot reuse an old
delivery identity. The persisted journal retains selection metadata only; opening
it in a new client still requires fresh authorized delivery. Disconnect cancels secret-bearing workers and reports an
infrastructure failure after cleanup; no-secret workers retain reconnect grace.
An existing cleanup failure takes precedence over the connection-loss result.
Any failed worker cleanup drains the slot before capacity is released, including
across connection replacement. Process startup must reconcile owned sandbox
state before accepting new work. This does not claim erasure of transport-owned
raw buffers or arbitrary copies, or establish full composed rollout acceptance.
