# Closed controller bundle preparation

Preparation operates on an exact live journal-owned bundle and frozen job, not
an adopted directory. It constructs the closed OCI configuration, copies the
bounded hash-verified input inventory, and creates fixed private root/runtime
state directories before the measured child starts. The caller's descriptors
remain caller-owned; only independently verified copies reach the guest.

Configuration and input files are root-owned, single-link and readonly. The
input directory is root-owned and readonly. Only the bundle and private runtime
directories transfer to the trusted, exclusively allocated mapped identity.
Their exact inode identities and the sealed files' metadata are retained and
rechecked at process creation and gate release. Access times may change through
reads; ownership, modes, content timestamps, size and inode/link identity may not.
The mapped runtime cannot write root-owned sealed files or substitute a new
directory that passes those checks.

A partial preparation is terminal for that bundle and remains cleanup-owned.
A bad input does not disable unrelated jobs in the same journal. Once a prepared
proof observes changed configuration, inputs, mapping or private-root identity,
it cannot resume even if the caller later supplies the original values. The
existing process/bundle journals still own cleanup and cold recovery.

The real disposable Sentry fixture uses this path instead of manually writing
OCI configuration or transferring directory ownership. It retains the original
input-staging negatives and verifies that later source mutation cannot change
guest-visible bytes. Kernel tests cover job-local failure and irreversible
prepared-object drift. A real child behind its gate must refuse changed
configuration without producing guest output, then complete owned cleanup.

This is internal trusted-controller assembly, not a privileged RPC. Provisioning
must select and exclusively allocate the mapped IDs and the aggregate staging
ceiling. Global capacity/host-storage accounting, route provisioning/recovery,
runtime evidence and provider integration remain required before activation.
Command and environment values here must be non-secret configuration: secret
materialization belongs to a separate ephemeral channel, not persistent OCI
JSON. This change does not introduce that channel or enable production networking.
