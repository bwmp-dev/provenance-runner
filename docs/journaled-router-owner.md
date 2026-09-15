# Journaled controller router holder

`StartRouterOwner` creates a separate journaled process scope for a trusted,
credential-free router namespace holder. The fsynced cgroup ownership record
precedes process creation; the child is born inside that scope. Its user/network/
mount namespaces are fresh, with a trusted two-entry non-root host mapping and
empty supplementary groups. It executes only the retained measured runner.

The closed helper accepts five identity arguments and four fixed descriptors:
lifetime pipe, readiness pipe, retained runner and parent network namespace. It
accepts no command, environment override, host path, job artifact or PID. It
provisions no links, routes or DNS sockets. After checking its mapping and fresh
network namespace, it drops capabilities/bounding sets and enables no-new-
privileges on **every Go runtime thread**, not just the calling thread. This
requires a non-cgo runner; unsupported all-thread operations refuse startup.
Core/file writes and real-time priority are disabled, and open files are bounded.

Readiness is one byte followed by EOF, with a five-second parent deadline. Only
then does the parent retain the actual child identity and kernel resource proof.
The holder accepts no lifetime-pipe payload: EOF terminates it; any byte refuses.
Parent death uses SIGKILL, and context cancellation or process exit triggers
whole-scope cleanup. Cleanup is bounded, retryable and retires durable records
only after the complete owned cgroup is empty and removed.

This is a separate controller scope, using admitted policy ceilings beneath the
provisioned global cgroup boundary. It is not part of the workload's exclusive
scope and is not a global capacity allocator. The same cold journal recovery
drains recorded scopes before bundle recovery. Process cleanup alone does not
prove route/link cleanup or destruction of namespaces retained by other owners.
The outer controller must supervise holder loss and close all route references
before releasing identity/capacity reservations.

The disposable routed fixture uses this holder for real Sentry traffic, verifies
that workload cleanup leaves it alive, then verifies terminal/idempotent router
scope cleanup. Production controller selection and host wiring remain disabled.
