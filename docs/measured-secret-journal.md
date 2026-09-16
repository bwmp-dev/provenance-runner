# Measured secret-directory ownership

`OpenMeasuredBundleJournalWithSecrets` is an optional trusted constructor over
an independently provisioned, root-owned 0711 tmpfs parent. The ordinary journal
constructor remains unchanged. Neither enables secret-bearing job admission.

The persistent bundle intent records the kernel boot ID and tmpfs parent identity
before creating a job-named child. The owned record then captures that child's
device and inode before any values may be materialized. Canonical record decoding
rejects partial or contradictory secret metadata. Values and value hashes never
enter these records.

Cleanup drains the owned cgroup first, then removes the exact secret child before
retiring the bundle records. Recovery drains the cgroup journal before filesystem
recovery. Unknown children, changed inodes, same-boot parent replacement, symlinks
and mount crossings fail closed. Intent-only children must still be empty and
root-owned with mode 0700. Old-boot records authorize retirement only when their
tmpfs child is absent, never deletion of a current child. Failed cleanup retains
the owner and records; it does not advertise capacity.

Disposable fixtures cover normal retirement, cold reopening after cgroup
retirement, intent-only interruption, unknown children and replaced directory
refusal. Cold reopening is explicitly a lost-userspace-owner fixture, not a host
reboot or a fresh gateway secret delivery. Daemon provisioning, closed guest
mounts, late authenticated delivery and end-to-end lifecycle acceptance remain
required before production use.
