# Current network authority v2 (IFC-030)

This additive contract preserves literal authentication protocol `1`, released
field numbers/reservations, historical acknowledgements and legacy network-none
identity. It is not deployment, sandbox measurement, or a signed public claim.

## Negotiation and placement

`NETWORK_AUTHORITY_V2` (10) is negotiated independently on each authenticated
stream. Advertising it requires `NETWORK_POLICY_V2` (9), durable acknowledgements
(1), job correlation (3), and a complete enabled-workload authority consumer.
Roll out server recognition first; an older server may reject unknown features.
Do not silently remove a required feature to admit a job. The original feature-9
contract is retained for compatibility, but the current-authority profile cannot
be advertised, scheduled or downgraded as feature 9 alone.

On a negotiated stream, an accepted or active job with an enabled versioned
network policy requires `LeaseReconciliation.network_authority_v2` (17) on every
event or heartbeat acknowledgement. Omit it for a legacy or none policy, offered
but unaccepted work, terminal/cancelling work, or an unadvertising stream. Existing
terminal/cancellation handling still withdraws networking. Unexpected presence
is a protocol error. For an admitted enabled job, absence, malformed metadata,
unknown state or lost current authority immediately withdraws forwarding.

The enclosing lease ID, job ID, execution ID and every attempt-identity field
must match the runner's own admitted job. Lease expiry is checked as authoritative
renewable state, not required to equal the original offer's expiry. `policy` is
exactly SHA-256 (algorithm 1, 32 bytes), equal to the original complete canonical
effective-policy identity in `JobHashes.policy`. A hash is not independent proof
of authorization. Customer-provided values cannot create this observation.

## Current checks and finite lifetime

The gateway independently rechecks the authenticated runner/stream, current
credential validity, original frozen job/source binding and all five current
policy layers in a transaction for every delivery, including exact durable
receipt replay. The check must be current when the transaction commits. Neither
cached success, a lease extension nor historical receipt state substitutes for
it. Missing or withdrawn policy produces explicit `WITHDRAWN` when the exact
owned job can be reconciled. Authentication failure cannot produce a positive
observation. Unavailable infrastructure must not reuse cached permission.

`checked_at` records that check's current server time, independent of historical
acknowledgement `committed_at`. `CURRENT` requires `expires_at` strictly after the
check and reception, no later than the current authoritative lease expiry, the current
credential expiry, or 60 seconds after the check. The receiver permits at most
five seconds of future check-time clock skew; a future deadline is never inferred
from reception time. `WITHDRAWN` omits expiry and irreversibly stops this attempt's
forwarding. Unknown/unspecified states, extra unknown metadata fields and invalid
timestamps/digests are refused. An invalid positive observation is not repaired
by narrowing its deadline or changing the original policy.

Historical reconciliation may contain an older lease expiry after a newer renewal
was acknowledged. The receiver bounds the observation by the latest independently
acknowledged expiry for that exact lease (including this reconciliation), not only
by the old replay's expiry. Authority metadata never extends the lease itself. A
deadline beyond all locally acknowledged lease state is refused. The gateway must
still use the actual current lease expiry in its new authority transaction.

Current observation metadata is excluded from the historical receipt state,
payload hash and replay reproducibility just as transport delivery metadata is
distinct from committed state. It contains no credentials, resolver endpoints,
namespace selectors or secret capabilities. Attach it only after the current
authority transaction commits. An exact replay can therefore carry a newly
checked observation without changing the old receipt or `committed_at`.

## Ordering, renewal and withdrawal

`STALE` is not a revocation signal: an old heartbeat can legitimately follow a
newer accepted renewal. Validate its current authority metadata independently of
that disposition. An older positive check cannot extend the last accepted
authority deadline; identical check times must retain the same deadline. Newer
positive checks can extend permission only while the prior authority is still
live. Once authority expires or is withdrawn, this attempt cannot resume, even
if a later observation is positive. Normal new-attempt admission is required.

Installed kernel forwarding and controlled DNS may live no longer than the
earliest current authority, lease or validated address-binding deadline. DNS
refresh cannot extend authority; lease renewal cannot replace a current check.
Refresh must preserve connection accounting and byte budgets. Cancellation,
connection-authority loss and restart fail closed. A transport reconnect never
restores an expired/withdrawn attempt; an unexpired existing guard still requires
the new stream's negotiation and fresh checked authority before extension.

Withdrawal must stop established and new traffic before any cleanup/capacity
claim. It does not synthesize candidate cancellation, a terminal receipt or a
successful cleanup. The ordinary classified terminal path and owned resource
teardown must still complete. Retain capacity/quarantine on unproven cleanup.
Backend producer and runner/provider acceptance, immutable job compatibility,
measured runtime and controlled rollout/rollback remain activation prerequisites.
