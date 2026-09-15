# Router-owned forwarding setup

The closed router child enables IPv4 and IPv6 forwarding before reporting
readiness. It disables IPv4 redirect generation and IPv6 router-advertisement
acceptance for both existing and future interfaces. Paths and values are fixed
in trusted code, not supplied by a workload or RPC caller.

Setup follows exact UID/GID-map checks, validation of the lifetime/readiness
pipes, and proof that the current network namespace differs from the retained
parent namespace. Its interface inventory must contain only loopback. Each
sysctl is opened without following a final symlink, checked to be procfs,
written without creating a file, closed, reopened and read back with a three-byte
bound. Any unavailable control prevents readiness.

Only after setup does the helper drop every capability set on every Go thread,
set no-new-privileges and lower resource limits. No setup handle is retained.
Partial setup belongs solely to the fresh journaled router namespace: failure
terminates that owner rather than changing or rolling back host networking.

The disposable measured fixture no longer has a separate forwarding writer.
Actual IPv4/IPv6 Sentry traffic exercises this startup path, while the existing
all-thread privilege checks remain mandatory. Parent sysctls are compared before
and after router startup and again after cleanup.

Forwarding is not permission: the workload remains gated until prepared layout,
measured resources and installed policy are verified. This change does not
provide a host uplink, NAT, DNS service, global reservation, root RPC or hosted
acceptance, and does not enable production network execution.
