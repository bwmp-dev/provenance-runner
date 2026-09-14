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
the actual installed kernel policy **before** releasing the measured child's
launch pipe. The resulting Sentry executes the non-root guest from the retained
read-only root mount, not the old pathname-only fixture root.

Each withdrawal and independent-expiry case is repeated three times. Both
families and TCP/UDP exercise allowed traffic, denied destinations/metadata and
wrong ports/transports. Established flows survive renewal and a shorter current
authority deadline without resetting accounting. After withdrawal or expiry,
existing and new flows are denied while the synthetic endpoints remain alive.
New positive authority cannot revive the stopped owner. Final checks validate
retained measured objects, reject authority reuse, inspect all owned namespaces
for leftover nftables tables, and detach the exact owned image loop.

The CI driver requires all six real test results, no skipped or failed cases and
the explicit successful loop-detach observation. Checker unit tests require
missing cases or cleanup evidence to fail. Evidence includes the exact source,
fixture image, builder hash, root image hash, test binary hash and captured test
results. There are no production credentials or external test endpoints.
