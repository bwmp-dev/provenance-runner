# Default resolver in measured network jobs

Prepared network bundles now contain a fixed `resolv.conf` alongside the OCI
configuration. Its only nameserver is the owned router at `10.0.1.1`; timeout
and attempt counts are bounded. Preparation writes it exclusively, synchronizes
it, makes it root-owned/read-only and records its immutable identity. It is not
copied from the host or selected through job arguments, environment or inputs.
Identity or permission drift permanently refuses prepared-bundle validation.

The closed measured OCI constructor adds exactly one read-only, nosuid, nodev,
noexec file binding to `/etc/resolv.conf`. The measured process owner requires
that target to be a regular file on its retained SquashFS image, using
descriptor-relative no-symlink/no-mount-crossing resolution. Missing targets,
symlinks and foreign mounts refuse launch; they are not silently repaired on
the execution host.

The reproducible image builder preserves an existing regular resolver target,
creates an empty read-only target if absent, and refuses symlink/non-file
targets or a redirected `etc` parent. This changes newly built image identity;
it does not replace or repin an installed image. The actual per-job nameserver
configuration comes from the separate protected bundle binding.

Disposable guest tests use the default resolver, with no custom dial function,
for exact A/AAAA answers and unlisted-name refusal. They also check the fixed
file contents and refusal of a write, alongside the existing explicit UDP/TCP
DNS checks, packet/confinement assertions, DNS failure shutdown and cold
recovery. Prepared resolver permission drift is restored only for cleanup and
cannot restore launch permission. Builder tests cover unsafe target shapes and
actual reproducible, exclusive SquashFS output.

This makes standard resolver consumers usable with controlled DNS. It does not
enable production network admission, replace policy bindings, prove real Paper
execution, or grant host forwarding, NAT or global reservations.
