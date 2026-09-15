# Measured Paper guest preparation and output

The fixed `provenance-measured-paper` entry point refuses host/root identities:
execution requires guest UID/GID 65532, no command-line overrides and a bounded
canonical bootstrap description on standard input. The signed input plan derives
that description only for its exact job. It contains file identities, archive
layout and resource limits, not URLs, host mounts, arbitrary commands or secrets.

Before creating a mutable workspace, preparation retains and hashes the fixed
read-only input files. Java and prepared-runtime archives stream directly into a
new guest-owned workspace without a duplicate cache. The shared archive reader
keeps expansion, entry, cancellation and link-containment checks. Prepared runtime
top-level entries are limited to real cache/libraries/versions directories; they
cannot prepopulate independently owned plugin/configuration roles. File copies
are exclusive and rehashed. Initial expanded data, copied inputs and configuration
allowance must fit the workspace half of the existing split tmpfs quota; kernel
memory/disk limits still bound actual growth and filesystem overhead.

Java invocation is derived without a shell, with a closed environment and bounded
heap arguments. Guest extraction occurs after sandbox release, within the host's
execution deadline. Host preparation still covers input copying and session
construction. Failed guest preparation is an infrastructure failure, not a plugin
compatibility result. Java exit 125 is remapped to 126 to preserve the helper's
reserved infrastructure status.

Java stdout/stderr are separately framed, sharing the configured log-byte cap
(maximum 16 MiB). Exceeding it cancels Java. The fixed guest-tmpfs event file is
retained before Java starts; replacement, oversized content or observed mutation
is refused. At most 4 MiB of event bytes are framed after Java exits. An outcome
record follows cleanup. Frames are bounded to 32 KiB and serialized across output
streams. All guest output, including the outcome, remains untrusted: host consumers
must enforce total bounds, validate event schemas and independently observe actual
process exit and complete sandbox retirement. Framing is not execution evidence.

The image builder optionally accepts `--paper-guest` and `--paper-guest-sha256`
together. It checks a bounded static amd64 ELF profile, verifies the source and
copied bytes, installs the exact helper as `/provenance-measured-paper` mode 0555,
and records its digest in the twice-reproduced image result. Existing source
objects at that path are not overwritten. A retained-image check requires the
fixed regular executable inside the measured SquashFS before Paper launch.

Mandatory disposable acceptance runs the real helper under the owned measured
controller and pinned Sentry three times, with a synthetic Java executable.
Success checks prepared file roles, read-only inputs, distinct stdout/stderr,
events, outcome and complete retirement. A missing Java layout must report an
infrastructure refusal and retire all owners. Unit tests additionally cover
aggregate quotas, altered inputs, malformed bootstrap data, framing and archive
failure cleanup. Image-builder tests cover pinned copies and dynamic/changed or
pre-existing helper refusal.

This does not claim real Java/Paper plugin compatibility, sealed test-secret
injection, root RPC dispatch, worker-side output/evidence integration or production
activation. Those remain required. No host FIFO, arbitrary executable mount,
management credential or legacy network-v2 fallback is enabled.
