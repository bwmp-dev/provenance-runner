# Authenticated acknowledgement integration

The gateway session copies its advertised feature set after authentication.
Only acknowledgements that pass pending/remembered message identity, sequence,
cardinality, lease/attempt and normal reconciliation validation reach the
authority consumer. Unmatched metadata, legacy/none metadata and metadata during
terminal/cancellation cleanup are refused. Enabled jobs require feature 10 and
its released dependencies plus the actual stream credential expiry.

Each live admitted attempt gets one private in-memory guard. A heartbeat or event
can refresh that guard without changing the original policy or journaling an
authority grant. STALE is not revocation, and old lease receipts cannot regress
independently acknowledged expiry. Malformed metadata withdraws forwarding and
does not advance the journal. Valid subsequent receipts may settle bookkeeping
for a stopped attempt but cannot revive it.

Explicit withdrawal before worker invocation skips preparation/renewal/reissued
progress and queues the ordinary owning infrastructure-failure event. It does
not invent cancellation, runtime evidence, successful cleanup, or release the
active lease. A running worker instead returns its ordinary classified result
after cleanup. Deferred results retain priority over the pre-worker failure path.
Failed owned teardown drains the runner and cannot authorize slot reuse.

Stream loss withdraws only the matching connection generation. Reconnect may
finish cleanup/terminal bookkeeping but never restores the stopped guard. A
process-recovered job validates incoming metadata without constructing a guard;
the existing restart-failure path remains responsible for it. A distinct admitted
retry requires a new guard after prior cleanup. Worker cancellation/expiry also
withdraws networking before waiting for the worker result.

Tests exercise session acknowledgement handlers and the worker bridge using
synthetic, directly injected accepted-job fixtures. Production offer/Paper
admission and capability advertisement remain fenced, so these tests do not
claim a production network-enabled gRPC/Paper execution. The independent live
Sentry route/expiry/withdrawal fixtures are retained as a separate required gate.
Production namespace/helper wiring, measured runtime identity, hosted acceptance,
record trust and rollout/rollback remain required. No production deployment or
network activation is performed here.
