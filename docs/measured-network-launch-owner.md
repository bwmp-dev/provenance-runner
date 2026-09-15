# Controller-owned measured network process

`StartMeasuredNetworkProcess` is an internal Linux launch boundary for a trusted
root controller with empty supplementary groups. It accepts an admitted job,
fresh authority owner, measured runtime lease, newly journaled job cgroup, its
matching durable journal, trusted
mapped identities, private root and standard file descriptors. It accepts no
arbitrary command, runtime flags, environment, generic I/O callback or adopted
PID. It is not an RPC endpoint or a production provider selection.

It also requires the exact live [journaled bundle](measured-bundle-journal.md).
The bundle records and the actual directory behind its private-root path are
checked before starting and again at gate release. Process-owner cleanup still
retires only the process scope; the outer bundle journal preserves independent
file ownership until subsequent bundle cleanup or cold recovery completes.

The bundle must also have completed [closed preparation](measured-bundle-preparation.md).
Startup and gate release recheck the sealed configuration/input identities and
the exact prepared mapped identity; caller-provided OCI files are not accepted.

The process independently retains the measured objects, uses the closed measured
network-child command, creates private user/network/mount namespaces, and is born
inside its owned cgroup. Before returning, it retains the direct child's kernel
identity and verifies its actual resource boundary. The launch pipe remains
closed to execution until `Release` revalidates measurement, resource membership
and the authorized native route for that exact retained child.
`Release` also requires the [owned private link](private-job-link-owner.md) for
that native route's exact router and workload. The process borrows this proof;
outer teardown must close the route and link before releasing their namespace
and capacity reservations.
Resource validation also requires the exact retained child object, not just
matching job/attempt labels. Nil or foreign owners permanently invalidate that
resource proof; retrying with the original child cannot revive it. Refusal does
not kill either process or invalidate an independently retained resource proof.
The disposable fixture checks this with a living router bearing the same job ID,
as well as a nil owner, before launch and validates the real workload again after
guest execution starts. These checks alone do not produce runtime evidence.
The matching journal and both original durable records are checked before
creation and again at gate release. A missing, foreign or corrupt record refuses
launch; corrupted ownership also poisons future scope launch descriptors.

An independent write-only child readiness pipe reports exactly `r` then EOF
after initialization and mapping checks, before the child waits on the launch
pipe. The controller bounds this wait to five seconds and observes resources
only afterward. This prevents Go's startup adjustment of the open-file limit
from racing the observation; it does not ignore changes, retry failed proofs,
or treat readiness as permission to launch. Missing readiness fails closed.

Cancellation or authority loss triggers whole-scope cleanup independently of a
caller polling `Wait`. Main-process exit triggers cleanup as well, without the
process owner itself withdrawing authority and manufacturing an authority-loss
error for normal completion. `Wait` returns the actual process result together
with cleanup errors. `Close` is irreversible, bounded and retryable; a failed
cleanup retains references and is not permission to delete the workspace.
Successful cleanup includes durable retirement of both ownership records, not
only process termination. Repeated cleanup of the exact retired object is safe
without an unbounded completed-object registry in the journal.

Every non-nil constructor result owns the supplied scope, including failures.
A nil result leaves scope cleanup with the caller. Standard streams are concrete
files duplicated into the child by exec; callers retain ownership of their own
copies. The returned child identity is borrowed for native route construction
and must not be closed by the caller. The outer authority supervisor still owns
route teardown and the remaining mount, disk, artifact and reservation cleanup.

The real protected-image fixture exercises owned launch, admitted guest traffic,
live renewal and termination after authority loss; a separate normal-exit case
checks successful completion without self-induced withdrawal. A corrupted
journal while a real child waits behind the gate must refuse launch, produce no
guest output, and retire the failed attempt's scope and records. Existing explicit
packet withdrawal, expiry and wrong-child cases remain mandatory. Missing cases
or exclusive-scope/image cleanup evidence fail acceptance.

Thirty additional gated-startup subcases exercise early resource observation
and whole-scope cleanup without ever permitting guest execution. Resource
refusals report only fixed observation-stage labels, never procfs contents.

Namespace liveness uses the retained pidfd before and after identity checks.
An interrupted nonblocking poll supplies no observation, so it is completed with
at most eight calls against that same descriptor. Exit events and all other
errors refuse immediately; a signal flood also refuses after the bound. The
disposable namespace fixture sends SIGURG to the observing thread during 256
checks of a living child, exercising the runtime-signal interruption that can
otherwise falsely refuse startup or renewal. This does not retry an observed
identity change, adopt another process, or revive withdrawn authority.

Production activation remains blocked on trusted OCI construction/provisioning,
durable controller recovery, provider/result integration and hosted acceptance.
The credentialed runner must not be elevated to root to call this API. No public
host-path, PID or privileged command endpoint is authorized by this change.
