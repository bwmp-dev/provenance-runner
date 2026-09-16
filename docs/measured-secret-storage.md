# Measured secret storage boundary

The private `stageMeasuredSecrets` helper materializes a sealed descriptor set
into an already-owned, empty tmpfs directory. It is not yet connected to service
admission and does not enable secret-bearing jobs.

It checks root ownership and exact initial permissions, refuses persistent
filesystems, validates names and sealed read-only descriptors, bounds the whole
set to 64 files and 64 KiB, and checks cancellation and expiry before writing.
Every temporary value buffer is cleared on return. Files are exclusively created
as root-owned read-only regular files. The completed directory remains root-owned
with mode 0550 and the provisioned mapped group, so the runtime can read but
cannot chmod it or create entries; repeated materialization is refused.

The disposable bundle fixture exercises actual tmpfs materialization, mapped
non-root reading, exact inode permissions, and expired, cancelled, invalid-name,
duplicate, aggregate-overflow and persistent-storage refusals. These are storage
tests, not evidence of completed job-secret delivery or crash recovery.

Before wiring this helper into the root service, composition must provide:

- Durable ownership intent before creating the job-private tmpfs subtree, with
  inode and boot identity checks during recovery.
- Whole-cgroup and gofer retirement before deleting that subtree or releasing
  capacity; failure must preserve the owner for retry.
- A closed read-only, nosuid, nodev, noexec guest mount that exposes only this
  job's files, never the shared tmpfs parent or worker descriptors.
- Fresh, authenticated delivery after slow input preparation, bound to the
  original job, selected references, accepted lease and attempt; values must
  reach neither persistent configuration nor journal records.
- Redactor registration before Java release, expiry refusal, and composed
  cancellation, disconnect, recovery and real-Paper acceptance.

The helper does not erase swap or debugger copies and does not authenticate
wire peers, selections or expiry itself. Its caller owns partial files on every
failure; it must not use a workspace or persistent fallback.
