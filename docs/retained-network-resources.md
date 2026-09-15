# Retained mapped-runtime resource observation

`RetainedResources` is a read-only, fail-closed observation of a trusted
controller's own retained mapped child. It owns a duplicate of an already
provisioned cgroup directory descriptor and binds the original full policy hash,
job/lease/execution and complete attempt identity. It creates, changes, kills and
removes no cgroups or processes. Closing it releases only that descriptor.

Validation requires an actual root-owned, non-group/world-writable cgroup v2
directory and protected kernel control files. The child's exact unified cgroup
membership is resolved beneath the actual cgroup mount and must identify the
same retained kernel object. Child liveness, namespace ownership and membership
are rechecked after reading the controls; mutable pathname replacement is not
followed by the retained object.

The observed domain must have finite CPU, memory and process limits no greater
than the original policy. The process ceiling includes exactly the existing
17-process runtime/gofer reserve, not an extra guest allowance. Swap and CPU
burst must be zero. CPU quota comparison uses overflow-safe integer arithmetic.
Every observed thread of the mapped child must be in a fair scheduling class,
and the process must have zero soft and hard realtime-priority allowance.
Subsequent observations must retain the original
limits and owner; mismatch permanently invalidates this observation object.

This is not permission to run, network authority, a historical execution record,
disk-quota evidence or proof of exclusive capacity reservation. The trusted
controller must separately prove those obligations and withdraw/clean up when
resource validation fails. Root/kernel administrators remain trusted.

Importantly, current membership alone does **not** prove where earlier memory
was charged. A production launcher must create the child with
`CLONE_INTO_CGROUP` (Go's `UseCgroupFD`) before it allocates runtime memory, not
move an already-running process into a bounded group. CPU bandwidth controls
also require the appropriate scheduler class. See the
[kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The measured routed fixture now creates each mapped child using `UseCgroupFD`,
with the kernel limits independently provisioned by its fresh Docker container.
It checks real resource enforcement before releasing the measured launch gate
and again while the non-root Sentry guest is sending traffic. Negative cases
refuse actual kernel ceilings above a lower original policy and refuse owner
mismatch/revival without killing the child. Ordinary unit tests cover malformed,
unlimited, overflowing or missing controls, non-cgroup files, ambiguous paths
and scheduler/priority bypasses. Production provider and admission fences remain
unchanged.
