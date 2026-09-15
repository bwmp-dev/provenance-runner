# Exclusive job cgroup ownership

`CreateJobCgroup` creates a fresh, root-protected cgroup v2 leaf beneath an
explicitly provisioned empty parent with CPU, memory and process controllers
already enabled. It refuses the namespace root and existing job names. It
never enables parent controllers, migrates a process, adopts an existing scope,
or kills a sibling. The immutable admitted job, lease, attempt and full policy
digest bind subsequent launch descriptors.

The leaf has finite policy-bounded CPU, memory and process limits, zero swap,
zero CPU burst and no permitted child cgroups. Launch uses a duplicated
close-on-exec descriptor with `CLONE_INTO_CGROUP`, so allocations begin within
the boundary. `RetainedResources` must still verify the real mapped child and
its scheduler; cgroup creation alone is not runtime attestation.

Cleanup permanently closes admission, sets the process ceiling to zero, invokes
`cgroup.kill`, waits for `cgroup.events` to report no live processes, checks the
retained directory identity, and removes that exact leaf. Each call is bounded
to five seconds and may be retried; a timeout is never success. Removing the
cgroup also prevents launch through an older duplicated descriptor. These
semantics follow the [kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The caller owns every non-nil constructor result, including partial failures,
and must complete cleanup. A trusted-administrator rename or unexpected object
replacement fails closed instead of following the new pathname. A controller
must journal construction and recovery before using this API in production;
this API does not recover a scope by name after a crash. Scope removal does not
prove disk, route, mount, artifact or reservation cleanup, nor immediate release
of all dying-cgroup kernel charges. Those remain separate completion gates.

The disposable acceptance test uses an explicitly private cgroup namespace in a
new network-none container. It verifies a non-root descendant survives launcher
exit, actual whole-leaf cleanup, stale-FD launch denial, duplicate-name refusal,
wrong-lease poisoning, retry after cancellation, and survival of another live
sibling and the controller. All three repetitions are mandatory in packet CI.
No production service or network capability is enabled by this change.
