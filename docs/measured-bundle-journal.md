# Measured job bundle ownership

The trusted controller's private bundle journal owns a dedicated root-owned
0711 bundle parent and a separate root-private 0700 state directory on ext4,
XFS or Btrfs. Provisioning must protect their ancestors. Retained descriptors,
exclusive locking, canonical bounded records and file/directory syncing anchor
ownership; a job label or worker-selected pathname is not cleanup authority.

A synced intent precedes directory creation. A second synced record binds the
actual parent and bundle device/inode before the cgroup is created or a bundle
handle is returned. A partial creation stops admission and preserves recovery
evidence. Existing directories are not adopted. Records contain the job, lease,
execution, attempt and full-policy digest, never credentials or renewable
authority. The journal holds at most 128 active bundles.

The measured process owner requires the matching live bundle, scope and journals
before starting and before opening its launch gate. Both durable bundle records
must match the original retained identity, and the private-root pathname must
resolve beneath the same actual bundle. This does not substitute for the
controller's separate OCI construction, verified input staging or unique mapped
identity allocation.

Normal cleanup first completes the exact owned cgroup's cleanup, then deletes
the owned bundle and finally retires its records. The process owner can retire
its cgroup records before outer cleanup; the independent bundle records remain
through that crash window. Startup recovery drains the dedicated cgroup journal
before deleting any bundle files. It never resumes a historical execution or
manufactures a successful job result.

Unknown entries, malformed records, mismatched parent/bundle identities and
populated intent-only directories refuse recovery. Cleanup walks only retained
directory descriptors, never follows symlinks, and refuses all nested mount
crossings, including same-filesystem bind mounts. It is limited to 4096 entries,
32 levels and the caller's cancellation context. These are traversal bounds,
not a promise that a broken local filesystem cannot stall a syscall. Failed
cleanup retains evidence and blocks admission; only the same original owned
object can be retried. No broad recursive chmod or host-path sweep is used.

Disposable tests deliberately exit a controller while a known non-root child
remains alive, and separately after its process scope has already retired.
Fresh controllers must drain the scope and remove the remaining owned files.
Additional tests protect foreign directories, replaced directory identities,
symlink/hardlink targets and nested bind-mount contents. The existing measured
Sentry packet, quota, renewal, expiry and launch-refusal cases also use this
journal and require empty bundle/process journals on completion. These are
process-crash tests, not power-loss or hosted recovery acceptance.

This is an internal ownership primitive, not a root RPC service or production
activation. Trusted provisioning, UID allocation, route lifecycle and recovery,
host staging/log bounds, global reservations, provider/results integration and
hosted acceptance remain separate requirements. Deleting a bundle does not by
itself prove complete route cleanup or release capacity.
