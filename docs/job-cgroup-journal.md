# Cleanup-only job cgroup journal

`JobCgroupJournal` owns a dedicated cgroup parent and a root-private state
directory on ext4, XFS or Btrfs. Trusted provisioning must protect the directory
and its ancestors and supply readable retained directory descriptors. Pseudo
filesystems, tmpfs, symlink/hardlink records, permissive modes and simultaneous
controllers are refused. A kernel file lock remains held while live handles
exist. The directory is not shared with other state producers.

Creation uses a fresh 256-bit random scope name. An exclusive intent record is
written and both file and directory are synced **before** cgroup creation. The
scope's kernel device/inode identity is separately recorded and synced before
returning a launchable object. Failed writes stop admission and retain evidence.
Records contain original job/lease/execution/attempt/candidate/matrix identities
and the full-policy digest, not credentials, routes, DNS bindings or renewable
network authority.

Startup recovery must succeed before admission. Canonical bounded records are
validated before mutation; unknown keys, duplicate fields, orphan owned markers
and unknown child scopes fail closed. A missing or rolled-back journal therefore
cannot silently ignore a still-existing scope. Unknown scopes are not adopted
or killed. Record count is limited to 128 scopes.

Recovery matches the kernel boot ID and retained parent identity. A same-boot
owned scope must also match the recorded device/inode before whole-scope cleanup.
An intent-only scope must be empty, since no child could legitimately launch
before the owned marker became durable. A different boot never authorizes killing
an existing scope. Absent old-boot scopes can retire their cleanup records without
restoring execution. The boot identifier is obtained from the kernel's
[boot ID interface](https://www.kernel.org/doc/html/v6.9/admin-guide/sysctl/kernel.html#random).

Only after cgroup cleanup succeeds are the owned and intent records deleted,
with a directory sync between deletions. Recovery returns process-scope cleanup
identities, not successful job results or released capacity. Routes, mounts,
workspace storage, artifacts and reservation accounting still need their own
recovery and completion evidence. No historical authority is resumed.

The measured process owner requires the matching live journal and checks both
records against their original in-memory identity before launch. Cleanup of an
exact already-retired object is idempotent; foreign object handles remain
invalid. Successful process-owner cleanup includes durable record retirement.

Disposable acceptance uses a real persistent local filesystem and exits a helper
with `os.Exit` to bypass all normal cleanup, leaving either an empty intended
scope or a live non-root descendant. A fresh controller recovers both. Tests also
verify lock exclusion, no live-handle recovery, malformed-record retention,
unknown-scope refusal, non-destructive boot/parent/inode mismatch, and refusal to
kill a populated intent-only scope. All cases run three times. These are process
crash tests, not simulated power-loss or production recovery acceptance.

The journal is an internal primitive. Production controller/service integration
and hosted acceptance remain gates; this change enables no production feature.
