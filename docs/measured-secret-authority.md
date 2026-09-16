# Authenticated late root secret delivery

The root daemon accepts an optional `secretRoot` only through its protected
operator configuration. It must already be a protected root-owned tmpfs parent.
The immutable measured image must contain an empty read-only-backed directory
at `/run/provenance/test-secrets`; enabling the option does not create or mount
host storage. Ordinary configurations continue to refuse selected-secret jobs.

Explicit admission validates selection names, IDs and versions against the
original normalized configuration. The root waits until its helper has started
and its live runtime observation has been sealed before accepting one delivery.
The delivery header and descriptor batches use the same ordered channel as
authority updates. No authority packet may interleave with those batches.

The root independently requires the exact selected names, a still-live accepted
lease ceiling, future delivery expiry, sealed read-only memory descriptors and
the bounded 64-file/64-KiB profile. Materialization is one-shot and uses the
journal-owned private tmpfs mount. Java release is refused until materialization
succeeds, and expiry is checked again before bootstrap. Invalid, missing,
duplicate or late delivery cancels the owned session; ordinary cgroup-first
retirement retains all cleanup obligations.

The client callback runs only after root observation and before Java release.
Its caller retains descriptor ownership through the session and must configure
redaction before returning. The worker's normal acquisition and evidence
composition are deliberately not enabled by this primitive. Production protocol
advertisement and network activation remain off until those paths, no-network
execution and operator provisioning receive their own acceptance.

Unit tests cover accepted renewal ceilings, immutable selection mismatches,
explicit provisioning and ordered one-shot descriptor batching. Disposable
kernel fixtures exercise selected-secret read-only guest access and bypass the
worker validator to test root refusal of missing and expired deliveries, then
require the root idle barrier and journal/cgroup retirement. A passed test must
be recorded separately; merely adding these cases is not acceptance evidence.
