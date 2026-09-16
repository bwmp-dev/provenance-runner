# Measured network child handoff

This internal command is a building block, not a network-enabled production
provider. Existing runtime snapshot validation, network admission and capability
advertisement fences remain unchanged.

The owning trusted controller must create its direct child with private user,
network and mount namespaces. Exactly two non-root host identities are mapped:
namespace root and the overflow identity. Supplementary groups must be empty.
The child refuses inherited controller network/mount namespaces and accepts no
caller-selected runsc flags. The fixed Sentry configuration uses sandbox network,
systrap, no raw sockets, no host Unix sockets/FIFOs, no direct filesystem access
and a separate gofer network namespace.

Descriptors 3–7 retain the measured root, sandbox executable, runner executable,
backing SquashFS image and read-only loop device. Descriptors 8–9 retain the
controller network/mount namespaces solely for the isolation check. Descriptor
10 is a read-only pipe. Exactly `s` followed by EOF authorizes launch; wrong,
missing or additional bytes refuse execution, with a 30-second deadline. No
namespace or evidence descriptors are inherited by the executed runtime.

Descriptor 11 is a separate write-only readiness pipe: the initialized mapped
child writes exactly `r` then closes it before waiting on descriptor 10. The
controller waits for this bounded readiness signal before observing resource
limits. It is never interchangeable with the `s` launch authorization token.

Before releasing that gate, a production controller must retain/prove ownership
of the child, install and observe its current authorized route using
`ObserveInstalledForChild` with that exact retained workload owner, and create
the whole workload/runtime/gofer tree inside the exact aggregate resource
boundary from birth. A job-only observation or moving an already allocating
process into a cgroup is insufficient.
The command ignores runsc-managed cgroups because that outside aggregate boundary
is the controller's responsibility. The command alone proves none of these
controller obligations and is not exposed as a privileged service endpoint.

The closed handoff also carries canonical CPU millicores derived from the
authenticated job. After the launch gate, an OS-thread-locked child narrows its
inherited affinity to `max(2, ceil(millicores/1000))` available CPUs before exec.
This bounds runtime parallelism on large hosts; it grants no extra CPU time and
does not replace or raise the owned cgroup's CPU, memory or PID limits. A host
with fewer available CPUs retains that smaller set. The controller's affinity
is untouched. See [runtime CPU budget](measured-runtime-cpu-budget.md).

After gate release, the same retained-object mount implementation used by the
network-disabled launcher revalidates the image hash, backing inode, loop mapping
and read-only SquashFS mount, clones the retained mount into the private target,
and executes the retained sandbox descriptor. A read-only empty sidecar directory
selects embedded execution without changing explicit operator release policy.

Unit tests cover closed arguments, exact two-ID maps and bounded launch framing.
`TestMeasuredNetworkRootHandoff` runs only in a freshly provisioned disposable
container with an actual protected image/loop: invalid authorization is rejected,
and valid authorization executes a non-root synthetic guest through the real
measured mount handoff. It has no WAN and is not routed-packet, resource-limit,
hosted Paper or continuous runtime-attestation acceptance. Existing measured
network-disabled and protected-image negative fixtures still run alongside it.
