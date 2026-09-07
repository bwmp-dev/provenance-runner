# Execution-bound runtime measurement (opt-in)

The legacy directory-rootfs path continues to emit `runtime:null` and partial
terminal evidence. Image measurement is not enabled by default. It does not
authorize signing, publication, or complete program acceptance.

The measured path requires the `systemd-user` driver so every trusted launcher
thread, runsc process, and guest remains inside the existing aggregate limits.
It does not increase the PID reserve, memory limit, CPU quota, or guest UID/GID
(65532). The launcher creates a private user/mount namespace mapping only the
unprivileged caller's UID/GID; it does not grant a host capability.

Administrator inputs are `PROVENANCE_MEASURED_ROOTFS_IMAGE` and optional
`PROVENANCE_MEASURED_LOOP_DEVICE`. The latter may name a private read-only block
node, avoiding permission changes to a shared `/dev/loopN`. The actual mount's
block identity and read-only loop mapping must match the opened complete image:
device/inode, zero offset and size limit, no encryption, and no nested mounts.
Protected publication paths, root-owned immutable image/executable metadata,
strict no-symlink opens, and pre/post observed hashes remain required. An
explicit invalid measured configuration fails; it does not silently downgrade.

The administrator must also explicitly select
`PROVENANCE_MEASURED_RUNTIME_MODE=embedded-executable`. Only this measured mode
selects an empty read-only private sidecar directory using gVisor's documented
`GVISOR_SIDECAR_BINARIES_DIR` mechanism. Ordinary unmeasured configurations retain
their existing helper selection. Inherited sidecar/release overrides and explicit
sidecar policy flags are rejected, not overridden. The mode supports ordinary
network-none execution, not checkpoint restoration or helper-dependent modes.
It requires a gVisor release that still supports executing the embedded Sentry;
releases requiring separate helpers fail closed. The frontend hash must never
be presented as the identity of an on-disk Sentry or prewarmer. No installed
helper is removed or changed by this mode.

The runner executable is opened through `/proc/self/exe`; the gVisor ELF is
opened, hashed, and queried for its version. Retained descriptors, not a second
configured executable pathname lookup, drive the launcher. The private child
reopens the mount into its new namespace, validates the same immutable root and
loop/image identity, clones that **opened** mount, and attaches the clone at its
private OCI root. A raw inherited `/proc/PID/fd/N` root path is not usable as
runsc's gofer self-bind destination; that failed diagnostic is not acceptance.

Only observed runtime fields are projected. A measured runtime can still have
partial assertion coverage. Optional planned requirements and unsupported
operators remain partial, matching the released consumer; complete requires
every planned entry to be supported and observed. Complete coverage can contain failed assertions;
it does not mean the job passed. Durable replay validates original frozen bytes
without remeasuring an upgraded installation. Historical null-runtime proof is
not backfilled.

`scripts/build-measured-rootfs.py` is a build-only tool: it verifies explicit
source and builder SHA-256 pins, preserves archive ownership plus the required
runner-owned mount targets, rejects unsafe archives, builds twice independently
with fixed ordering/timestamps/options, and writes an exclusive content-addressed
image. It does not install or mount the result. The resulting image identity is
for the exact source, builder and selected UID/GID, not a universal image pin.
CI provisions the exact Ubuntu Noble builder and compression-library package
bytes into a new root-protected task directory, never the global package store.
The host ELF loader and compatible glibc remain explicit prerequisites: this is
not a hermetic builder closure. Library selection is scoped to the image build,
not inherited by the measured runtime. Two actual builds must produce identical
image bytes regardless of successful package verification.

Privileged tests use only private disposable resources. The CI fixture creates
an absent temporary user/session, a private image and freshly allocated loop,
then removes only what it created and records cleanup. It never enables linger,
changes a production rootfs, or changes shared loop-device permissions.

The kernel, privileged provisioning, and trusted host executable loader remain
trust boundaries. This is not protection against malicious host root, a TPM
attestation, authenticated customer FIFO authorship, or an inferred hash of a
multi-executable runtime closure. Production conversion requires a separately
reviewed drained installation and rollback procedure after code acceptance.
