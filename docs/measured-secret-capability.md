# Explicit measured secret readiness

`PROVENANCE_MEASURED_TEST_SECRETS=enabled` is an operator-only startup opt-in.
It requires a measured service endpoint and
`PROVENANCE_MEASURED_NONE_PROVIDER=isolated`. The ordinary connection option
`--enable-test-secrets` is still independently required. No connection or job JSON
can enable this setting, and it does not activate network policy v2.

Startup first opens and reconciles both independently provisioned providers.
It then asks the root service for a dedicated secret-capability response on a
fresh authenticated Unix channel. The request and response are distinct from
the ordinary idle probe, echo a fresh 32-byte nonce, accept no descriptors, and
share a five-second deadline. A non-root peer, old service, ordinary idle reply,
wrong nonce, malformed reply, descriptor, cancellation or EOF cannot confirm
support. Refusal closes the connection and startup releases its instance locks.

The root serializes this check with execution and confirms it only when its
controller is idle, its pinned Paper image remains valid, explicit secret
storage is configured and retained, and the immutable empty secret mount target
is still valid. The reply is an instantaneous capability check, not a slot
reservation, runtime observation, lease grant or permission to acquire secrets.
Each subsequent selected-secret job still requires the complete late-acquisition
and root admission sequence.

The connected worker advertises support only when this root check succeeded and
the separate no-network provider also supports secret files. This avoids a
single global feature bit promising support for only one execution route.

Unit tests cover transport separation, descriptor ownership, non-root refusal,
configuration and dual-provider advertisement. Disposable fixtures additionally
check malformed authenticated responses and actual configured/unconfigured root
services after retirement. Actual fixture results and production deployment must
be recorded separately; the existence of these tests is not acceptance evidence.
