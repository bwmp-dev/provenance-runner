# Closed measured-network guest configuration

The internal Linux constructor derives CPU, memory, process and writable-storage
limits from the complete hash-validated frozen job. Its guest-command input has
no host mounts, namespace paths, resource overrides, identities or runtime flags.
It does not enable the production provider or produce runtime identity evidence.

The shared OCI layout keeps the measured root read-only, drops all capabilities,
uses guest UID/GID 65532 with no supplementary groups and no-new-privileges, and
sets fixed resource limits. Writable guest files use separate bounded tmpfs mounts
at /workspace and /tmp whose sizes sum to the admitted disk limit. The small /dev
tmpfs is root-owned and not a general writable guest directory. Inputs have one
fixed read-only, no-execute bind beneath the controller-owned job bundle. No host
FIFO, Unix socket or arbitrary additional mount is introduced.

The network namespace is fixed to the already isolated child's /proc/self/ns/net;
the closed measured handoff proves it differs from the controller namespace. The
OCI cgroup path is empty because the outer journaled owner places the entire
runtime in its exact retained cgroup at birth. A requested network label cannot
select this path through the existing network-none provider.

This constructor is deliberately not a privileged RPC. The trusted controller
must still create and retain its private bundle and regular-file-only inputs,
verify downloaded objects, prevent host-path replacement, bound host staging and
logs, and complete route, mount, artifact and reservation cleanup. Guest tmpfs
limits are not a claim that all host disk usage is bounded or recovered. Paper
structured-event mediation remains a separate integration requirement.

The measured packet fixture uses this constructor with a two-MiB writable limit.
Inside the actual non-root Sentry guest, each one-MiB tmpfs must return ENOSPC,
the root and inputs must refuse writes, and the working directory must be private.
Original packet allow/deny, live renewal, withdrawal, expiry, journal-refusal and
whole-scope cleanup tests remain mandatory; writable-storage failures must not
silently replace the network assertions.
