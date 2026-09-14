# Current authority and owned route supervision

`AuthorityRoute` privately owns one `Authority` and one `RouteSession`; callers
cannot renew either independently through its API. Construction grants nothing.
A fresh authenticated accepted/active reconciliation is required before route
installation. The stream owner still authenticates and matches acknowledgements
before passing them in; this supervisor does not create authentication evidence.

Every DNS binding must retain the full original grants/caps and is bounded by
current authority before installation or refresh. A fresh shorter deadline
atomically replaces forwarding and both DNS-chain absolute deadlines before
publishing the replacement DNS view. The existing absolute `meta time` checks,
rounded down to seconds, prevent installation latency from extending permission
even though address sets also have relative timeouts. Equal/shorter replacement
is private to this supervisor; ordinary `Firewall.Refresh` remains extension-only.
Neither path recreates connection accounting, counters, or byte budgets.

Unchanged authority receipts do not reinstall rules. DNS refresh never extends
authority; changed route grants still fail closed. Original bindings are copied,
so later mutation by a caller cannot change a retained renewal snapshot.

An independent watcher expires authority even before installation. After start,
the route also independently expires at the earliest binding/authority deadline.
Either expiry, context loss, invalid metadata/profile, malformed DNS bindings,
failed actuation, or DNS-server failure permanently withdraws the attempt.
Concurrent reconciliation cannot resume it. Stable DNS sockets use the existing
route supervisor and do not reset transport budgets on refresh.

`Done` means the owner must stop work. It is **not** a cancellation receipt,
cleanup success, or capacity-release claim. Partial installation retains the
route. `Close` retries teardown, preserves actuation errors until a complete
cleanup retry succeeds, and cannot remove default-drop protection before an
independent disconnect succeeds. Namespace/resource ownership stays with the
trusted provider until its own cleanup is also proven.

Local acceptance includes the full runner race suite and five repetitions of the
authority/route tests. The explicitly prepared no-network disposable container
also runs the retained namespace/Sentry lifecycle, authority withdrawal, and
authority expiry cases three times each against the live endpoints. Both address
families and TCP/UDP are checked; established flows survive the reduced-but-live
deadline, then established and new flows are denied while the endpoint is still
alive. Later positive authority cannot resume the same attempt, and the owned
firewall is removed only after disconnection. These are synthetic isolated
packet fixtures, not production deployment or actual Paper job acceptance.

This change is enforcement composition, not production admission. Capability
advertisement and all production v2 offer/Paper fences remain unchanged. Gateway
worker integration, production namespace/helper wiring, measured runtime proof,
hosted acceptance and controlled rollout remain required. No deployment or
network activation is performed.
