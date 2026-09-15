# Measured terminal evidence bridge

Collected output and execution results retain an opaque `NetworkObservation`
in memory only. Collection preserves that object; JSON cannot serialize or
reconstruct its authority. `Result.FreezeTerminalEvidence` selects the sealed
network evidence builder, never a snapshot fallback. Missing execution context,
ambiguous simultaneous snapshot input, forged observations, and a changed
execution binding fail closed.

The gateway uses this same freezer after checking the active attempt and
authenticated runner identity. Measured network evidence also requires terminal
evidence v2, network-policy v2, and current-authority negotiation. Refusal occurs
before log upload, durable terminal queuing, or sending a result. Existing
non-network evidence and frozen-byte replay behavior are unchanged.

Measured Paper planning now projects v2 configuration and validates its complete
schema, configuration digest, policy identity, and network maximum through the
v2 terminal context. The legacy adapter remains v1-only; its network fences are
unchanged. Older v1 synthetic input-plan fixtures remain supported but cannot
produce measured v2 network terminal evidence.

The full-service disposable fixture uses a complete synthetic v2 configuration.
After authenticated root completion it freezes the real opaque observation via
the execution-result API and validates the frozen bytes. Reusing that observation
with a changed execution context is rejected. This tests producer authority;
historical frozen-byte validation does not reconstruct a new observation.
No probe lifecycle success is invented from the synthetic event. Separate tests
reject incomplete v2 configuration, network grants exceeding the configuration
maximum, missing environment identity, and unknown configuration fields.

This is an evidence transport bridge, not production activation. The connected
Paper worker, root daemon provisioning, measured secrets and actual Java/Paper
compatibility still require their own integration and acceptance.
