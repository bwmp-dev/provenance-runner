# Measured service request boundary

The local Paper request encodes a deterministic closed job protobuf and its
bounded signed runtime, not executable arguments or host paths. The worker first
projects the job by removing download/upload URIs and their expirations. Artifact
hashes, filenames, sizes, output object keys, attempt and policy identities remain.
Projection copies the input. Root decoding rejects a non-projected or
noncanonical representation, unknown fields, excessive recursion, malformed
lengths and trailing bytes. Runtime signature and local policy checks are separate
mandatory admission steps; decoding does not authorize execution.

The worker retains the original transfer capabilities. Both sides derive their
measured input plan from the same projection, not one side from the original job
and the other from the projection. The signed runtime contains only its existing
public asset locations; no HTTP fetch is needed to validate it locally. This
request adds no credentials or secret values. Application fields remain untrusted
input and must not be copied to host commands, configuration or diagnostics.

The authenticated sequenced-packet channel assembles a start request under one
deadline, at most 30 seconds. A fixed versioned header declares up to 2 MiB of
metadata and 256 read-only regular-file descriptors. Exact 64 KiB payload chunks
precede exact batches of up to 16 descriptors. This supports the full 1 MiB job
and signed-runtime envelope without weakening per-packet bounds. Role names,
sizes and hashes come from the root-derived plan, not descriptor metadata.

Any malformed, interrupted or out-of-order assembly closes the channel and all
received descriptors. A successful request transfers descriptor ownership to its
consumer and exposes the last sequence for subsequent control messages. Sending
borrows descriptors without taking their ownership. Only a fresh connection may
begin a request; retries require new authentication and fresh execution authority.

Renewal messages separately encode a canonical reconciliation, the negotiated
feature set and credential expiration, without an upload capability. They retain
the exact current authority observation and do not convert receipt of a local
message into permission: the root supervisor must still reconcile it against its
job and current clock. The released authority vectors continue to pass after
projection, including the rule that STALE alone does not mean revocation.

The controller can expose its actual owned process exit code only after complete
retirement. This uses kernel process state, not guest output; the disposable
Paper fixture compares positive and negative helper claims against it. It does
not replace the separate Wait result for cancellation or infrastructure failure.

Tests cover full-size payloads and all 256 descriptors, following-message
sequencing, transfer-capability removal and plan identity, malformed batches,
descriptor cleanup and partial-request deadlines. They execute no artifacts.
The root listener/dispatcher, independently observed terminal result, worker
integration and production provisioning remain separate work; this codec does
not expose a launch endpoint or activate network-v2 execution.
