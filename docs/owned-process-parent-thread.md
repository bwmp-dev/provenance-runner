# Measured process creating-thread lifetime

Linux parent-death signals are tied to the thread that creates a child. A Go
caller can return, migrate, or exit a locked OS thread while the controller
process remains alive. The measured workload and router owners therefore start
and wait for each direct child on a dedicated locked thread. Startup returns
only after `Start` completes; completion is delivered after `Wait`. The creating
thread is not unlocked before the child has been reaped. These semantics follow
the [Linux parent-death signal documentation](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

This private helper accepts only the two fixed measured executable roles, with
the existing cgroup-at-birth and SIGKILL parent-death configuration. Set-ID and
file-capability executable metadata is refused because privileged exec can clear
the parent-death signal. Artifact measurement, namespace mappings, readiness,
authority gating, cancellation and whole-cgroup cleanup remain mandatory in the
owning constructors. The helper is not a command-execution RPC.

The disposable normal-session test deliberately exits its locked calling thread
after construction. It verifies retirement through a retained task-directory
descriptor before running the full packet, DNS and cleanup assertions. Existing
controller-process-death recovery still requires both original scopes and the
uplink journal to be retired. Ordinary unit tests never launch these privileged
roles; they check refusal of incomplete command ownership and invalid targets.

The regression was first run against the previous constructors: all three
normal-session repetitions failed with unavailable owned DNS sockets after
caller-thread retirement, while the other session and cold-recovery cases
passed. This establishes that the test exercises the creating-thread defect.

This does not activate production networking or complete the privileged service,
global reservation or real Paper integration work.
