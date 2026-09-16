# Explicit network-v2 offer validation

The dedicated validator accepts only a completely negotiated v2 session with
durable acknowledgements, job correlation, terminal evidence v2, network policy
v2 and current-authority support. Missing, duplicate or unknown features,
disabled evidence and an absent/malformed trusted local maximum fail closed.
The old production offer validator continues to refuse every network-v2 policy.
This change alone does not advertise features or activate production scheduling.

The v2 path retains every existing bounded identity, expiry, tenant scope,
correlation, dependency, artifact, upload, resource and timeout check. It requires
an exclusive canonical v2 policy within the supplied local maximum. Complete
normalized configuration and policy/hash binding are validated through the
existing v2 terminal context, including the configuration's own network maximum.
The resolved environment's deterministic Protobuf hash is checked independently.
No policy narrowing, legacy projection, sorting or offer mutation is performed.

Secrets still need their separate negotiated feature and operator opt-in, plus
exact selected names/versions. An accepted offer supplies no current network
authority: a fresh accepted lease reconciliation remains required before any
enabled-network provider starts. Root admission independently enforces its
provisioned maximum and immutable job identity.

Tests cover none/restricted/allowlist acceptance, every required feature,
configuration and local maximum intersections, wrong tuple components, budgets,
hashes, scope, expiry, mixed/unknown policy fields, malformed configuration,
secret negotiation and immutable input preservation. Gateway advertisement and
live session composition remain separate acceptance gates.
