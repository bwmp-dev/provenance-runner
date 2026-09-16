# Late measured secret mount

An explicitly secret-provisioned bundle journal supplies a single derived mount
at `/run/provenance/test-secrets`, read-only, nosuid, nodev and noexec. Its source
is the job's recorded tmpfs child, not a caller-selected path or the shared
parent. The retained parent and its canonical pathname must identify the same
root-owned inode through protected ancestors. Ordinary journals add no secret
mount. A fixed 1-MiB metadata/content reserve is subtracted from the existing
guest temporary-storage budget; a job too small for that reserve is refused.
The immutable root must already provide the empty mountpoint.

Before launch the outer child remains root-owned with mode 0550 and the mapped
runtime's group. It contains a root-owned 0555 inner directory, which alone is
mounted into the guest. The outer directory restricts host access; the inner
directory allows the guest's distinct non-root virtual identity to read files.
Neither the gofer nor guest can change these directory permissions.
The private one-shot `stageSecrets` hook rechecks durable bundle ownership and
the child inode before copying sealed inputs. Failure consumes the attempt and
leaves the files with the cleanup owner. Materialization and cleanup share the
journal lock.

The synthetic Paper helper fixture supplies files only after the live helper's
runtime observation and before its Java bootstrap. The synthetic Java process
checks the exact file contents and directory inventory and refuses writable
files, file creation or chmod. The normal and preparation-failure cases retain
the existing full process, network and journal cleanup requirements.

This is a trusted in-process fixture. It does not yet authorize secret references,
provide the worker-to-root delivery protocol, register real delivery redaction,
or enable production secret-bearing jobs. Those composition gates remain closed.
