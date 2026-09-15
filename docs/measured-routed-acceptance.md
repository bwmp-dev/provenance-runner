# Measured routed execution acceptance

This test composes the real retained SquashFS mount handoff with the native
retained namespace actuator and current authority owner. It is not production
provider activation or hosted Paper acceptance. Resource-boundary provisioning,
the trusted production controller and runtime evidence integration remain gates.

The fixture builds the synthetic packet guest and gVisor test executable from
the exact checkout. A pinned Ubuntu container and SHA-verified SquashFS builder
produce a read-only image. A separate, fresh network-none container copies and
protects that image and the pinned Sentry executable, allocates only its own
read-only loop mapping, and mounts it read-only. No host network namespace or
installed runner root filesystem is attached. Privilege is fixture-only.

The root test controller creates and retains disjoint two-ID mapped router,
workload and synthetic WAN children. It installs the original full policy with
fresh authority, revalidates measured image/executable objects, and reads back
the actual installed kernel policy bound to that exact retained child owner
**before** releasing the measured child's
launch pipe. The resulting Sentry executes the non-root guest from the retained
read-only root mount, not the old pathname-only fixture root.

The fixture provisions a private cgroup namespace with the controller and
synthetic endpoints outside the job parent. The actual measured Sentry child is
born into a fresh `JobCgroup` leaf with its original finite CPU, memory, swap and
process limits. Retained resource observation checks that exact leaf before and
during execution. Whole-scope cleanup must succeed before removing the owned
bundle; afterward the job cannot obtain a new launch descriptor and the external
endpoint must still be alive. The container driver requires all job leaves to
be gone before reporting exclusive-scope cleanup. This is disposable composition,
not production provisioning, crash recovery or disk-quota acceptance.

Each withdrawal, independent-expiry, and wrong-child observation case is repeated
three times. The wrong-child case presents the living router owner with the same
job identity; it must withdraw the route, and presenting the correct workload
owner afterward must not revive it. Both
families and TCP/UDP exercise allowed traffic, denied destinations/metadata and
wrong ports/transports. Established flows survive renewal and a shorter current
authority deadline without resetting accounting. After withdrawal or expiry,
existing and new flows are denied while the synthetic endpoints remain alive.
New positive authority cannot revive the stopped owner. Final checks validate
retained measured objects, reject authority reuse, inspect all owned namespaces
for leftover nftables tables, and detach the exact owned image loop.

The controller-owned launch and normal-exit cases also repeat three times. The
launch case checks actual whole-scope termination after authority withdrawal;
the normal case checks successful process exit, cleanup and no self-induced
authority withdrawal. The original packet-level withdrawal cases remain intact.
Each owned-launch case also performs 32 consecutive DNS renewals against the same
living guest, retained namespace and budget objects before its flow and withdrawal
checks. Backend diagnostics preserve only sealed fixed stage labels; arbitrary
backend error text remains discarded.

Gated startup is also repeated three times with ten subcases each. Each child
must be successfully retained and cleaned up without release or guest output.

All scopes now use the cleanup-only durable journal. A seventh repeated case
corrupts the owned record while the actual child waits behind the launch gate;
execution must be refused and the failed attempt fully retired. The driver also
requires the journal to contain no outstanding ownership records afterward.

The CI driver requires all twenty-one real test results, no skipped or failed cases and
the explicit successful loop-detach and exclusive-scope cleanup observations. Checker unit tests require
missing cases or cleanup evidence to fail. Evidence includes the exact source,
fixture image, builder hash, root image hash, test binary hash and captured test
results. There are no production credentials or external test endpoints.
