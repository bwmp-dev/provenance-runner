# Released network v2 wire reader (inactive)

The Go protocol module is pinned to alpha.30 source
`2d4ae24ca251d7de2ef707901b5be75712e60836`
(`v0.0.0-20260913072252-2d4ae24ca251`). Public release
`v0.1.0-alpha.30` published those generated sources and the frozen vectors.
The vector extraction script checks both the previously independently verified
archive SHA-256 and the exact vector SHA-256 before writing its sole output.

Tests use the real generated module to reproduce enabled whole-tuple bytes,
the complete effective-policy bytes and SHA-256, and unchanged legacy bytes and
SHA-256. This is serialization compatibility, not acceptance of an authenticated
policy or proof of production enforcement.

The gateway offer validator and Paper adapter explicitly reject `network_v2`,
including mixed legacy/v2 and v2 `none`. The advertised-feature validator still
rejects feature 9. Reading the new field therefore cannot silently downgrade a
v2 job to the legacy `none` member. Existing connection/recovery paths continue to
use their current admission validation; no required-feature persistence, network
actuator, capability, policy evaluation, dispatch or production activation is
introduced here.

Actual DNS/firewall/Sentry fixture evidence remains documented separately in
`network-policy-acceptance.md`. Runtime integration and measured rollout are
required before the runner may advertise or accept enabled networking.
