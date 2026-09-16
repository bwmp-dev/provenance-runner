# Root-confirmed network capability

`PROVENANCE_MEASURED_NETWORK_V2=enabled` requires an explicitly configured root
service endpoint and `PROVENANCE_MEASURED_NONE_PROVIDER=isolated`. The connection
must also opt into terminal evidence v2. These settings remain disabled by
default and cannot be supplied by job or connection JSON.

The worker queries its authenticated root endpoint before connecting to the
gateway. A new nonce-bound, descriptor-free exchange returns only the root
controller's public effective-policy maximum. It returns no identities, paths,
credentials, resolver inventory or lease authority. The root confirms the
controller is actually idle and its pinned image and resource controls remain
ready. Responses are canonical closed Protobuf, bounded to 16 KiB plus a
32-byte nonce, and the exchange has one five-second deadline. Non-root peers,
wrong message kinds/nonces, descriptors, EOF, unknown fields and noncanonical
encodings fail closed.

Startup snapshots the verified maximum. Gateway capabilities contain its v2
network policy instead of the legacy network field, and resource capacity is
the intersection of connection settings and root limits. Caller mutations and
returned capability objects cannot modify the snapshot. Network policy and
current-authority features require durable acknowledgements, correlation and
terminal evidence v2 together. Rollback of either the network or evidence opt-in
withdraws network advertisement.

Only the advertised session snapshot may admit a v2 offer. Admission retains all
ordinary checks plus both configuration and root network maxima, root resource
and timeout ceilings, exact hashes and selected-secret metadata. Acceptance
persists the original specification and v2 evidence flag before acknowledgement.
It does not manufacture a current grant. The existing fresh-reconciliation
authority path remains mandatory; stream loss permanently withdraws the attempt.

Existing legacy no-network policies can still use the separate isolated provider
when terminal evidence v2 is selected. Their wire policy is not changed. v1
execution cannot enter the measured dispatch path, and enabled-network failure
never falls back to no-network execution.

## Verification boundaries

Unit/race tests cover startup gates, immutable limits, capacity intersection,
offer persistence, refusals and rollback. A generated gRPC stream fixture checks
that an offer alone never starts its synthetic worker, missing/expired authority
prevents startup, and disconnect withdraws a current grant while retaining the
unsettled journal and cleanup result. That worker does not launch a guest.

The separate disposable root suite adds actual maximum queries after each
retirement plus nine authenticated malformed-response cases. Its prior secret
capability suite took 177.92 seconds for 30 service cases within a 180-second
harness ceiling. The additional exchanges receive a 210-second service/220-second
subprocess ceiling and a 650-second outer ceiling. Individual job deadlines,
resource limits, output bounds and retirement checks are unchanged.

These tests do not establish production provisioning, full gateway-to-Paper
composition or live scheduling acceptance. Those remain activation gates.
