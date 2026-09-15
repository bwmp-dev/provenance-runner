# Controller-owned measured network process

`StartMeasuredNetworkProcess` is an internal Linux launch boundary for a trusted
root controller with empty supplementary groups. It accepts an admitted job,
fresh authority owner, measured runtime lease, newly owned job cgroup, trusted
mapped identities, private root and standard file descriptors. It accepts no
arbitrary command, runtime flags, environment, generic I/O callback or adopted
PID. It is not an RPC endpoint or a production provider selection.

The process independently retains the measured objects, uses the closed measured
network-child command, creates private user/network/mount namespaces, and is born
inside its owned cgroup. Before returning, it retains the direct child's kernel
identity and verifies its actual resource boundary. The launch pipe remains
closed to execution until `Release` revalidates measurement, resource membership
and the authorized native route for that exact retained child.

Cancellation or authority loss triggers whole-scope cleanup independently of a
caller polling `Wait`. Main-process exit triggers cleanup as well, without the
process owner itself withdrawing authority and manufacturing an authority-loss
error for normal completion. `Wait` returns the actual process result together
with cleanup errors. `Close` is irreversible, bounded and retryable; a failed
cleanup retains references and is not permission to delete the workspace.

Every non-nil constructor result owns the supplied scope, including failures.
A nil result leaves scope cleanup with the caller. Standard streams are concrete
files duplicated into the child by exec; callers retain ownership of their own
copies. The returned child identity is borrowed for native route construction
and must not be closed by the caller. The outer authority supervisor still owns
route teardown and the remaining mount, disk, artifact and reservation cleanup.

The real protected-image fixture exercises owned launch, admitted guest traffic,
live renewal and termination after authority loss; a separate normal-exit case
checks successful completion without self-induced withdrawal. Existing explicit
packet withdrawal, expiry and wrong-child cases remain mandatory. Missing cases
or exclusive-scope/image cleanup evidence fail acceptance.

Production activation remains blocked on trusted OCI construction/provisioning,
durable controller recovery, provider/result integration and hosted acceptance.
The credentialed runner must not be elevated to root to call this API. No public
host-path, PID or privileged command endpoint is authorized by this change.
