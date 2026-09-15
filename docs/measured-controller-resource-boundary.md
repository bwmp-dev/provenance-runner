# Aggregate measured-controller resource boundary

The serialized controller retains the dedicated cgroup journal parent by file
descriptor. Startup refuses the cgroup root, a populated parent, a non-domain
parent, missing CPU/memory/PID subtree controllers, or a changed parent identity.
It validates existing provisioning; it never changes host limits for a job.

The immutable local maximum determines this exact two-role profile:

| Parent control | Required value |
| --- | --- |
| `cpu.max` | Twice the maximum leaf CPU quota, period 100000 microseconds |
| `cpu.max.burst` | 0 |
| `memory.max` | Twice the maximum leaf memory bytes |
| `memory.swap.max` | 0 |
| `pids.max` | Twice (maximum job process count + 17 runtime threads) |
| `cgroup.max.descendants` | 2: one workload and one independent router |
| `cgroup.max.depth` | 1 |
| `memory.oom.group` | 1 |

Each role still receives its own exact per-job leaf limits. The parent bounds
their aggregate consumption. Hierarchy depth and descendant limits constrain
new cgroup creation; deleted cgroups can remain in the kernel's dying state.
Group OOM behavior has the kernel's documented protected-task exception and
does not expand a leaf OOM into an ancestor-wide kill. See the
[kernel cgroup v2 interface documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The journal refuses unowned scope creation or closure while the aggregate owner
is held. Controller admission, gate release and runtime observation validate the
retained profile. A 250 ms watcher detects live drift and cancels the active job;
this is periodic detection, not an atomic guarantee against a privileged host
administrator. Any failed validation permanently invalidates that owner.
Restoring the old values cannot resume it. Cleanup remains retryable and a new
controller requires retired jobs, recovered journals and valid provisioning.

Acceptance provisions these controls only inside the explicitly prepared,
network-none disposable container. Three real-Sentry repetitions change the
parent memory limit during execution, require an infrastructure failure and
complete cleanup, then prove restoration cannot revive the old owner. Existing
busy-slot, staging failure and cleanup-retry cases also exercise the owner fence.

This is not a persistent-filesystem disk quota, a controller-process resource
limit, a host identity allocation proof or an authenticated root service. Those
remain separate integration/provisioning requirements. No production profile or
network-v2 activation is performed by this change.
