# Session-owned phase deadlines

Each measured network session owns a cancellation budget independent of whether
its caller remembered to supply a context deadline. Construction starts a timer
bounded by the frozen preparation timeout. Immediately before the launch gate,
a one-shot transition replaces it with the frozen execution timeout. Expired
construction, repeated release, failed release and parent cancellation cannot
restart or extend a deadline.

These timers cancel the same lifetime context used by router/workload owners,
DNS renewal and the session monitor. Timeout therefore withdraws authority and
terminates the owned scopes through the existing cleanup path. Completion still
requires all process, route, DNS, uplink and bundle owners to retire; a timer
firing is not proof of cleanup or released capacity. Timeout causes remain
distinguishable from normal completion and generic cancellation.

Normal teardown stops the current timer. Transition stops the construction
timer before starting the execution timer, so the old phase cannot later kill
a healthy running job. The caller's earlier deadline still wins. The existing
graceful-shutdown policy is not extended by this hard execution bound.

Unit tests cover both expirations, phase transition, repeated release, invalid
budgets and parent cancellation. Disposable acceptance additionally blocks the
initial resolver until the construction budget expires, and runs a live job
until its execution budget expires. Both must preserve the deadline cause and
fully retire owned state; all seven session cases run three times.

The construction clock begins when this internal session takes ownership of an
already prepared bundle. The outer provider must still bound earlier artifact
download and preparation. This does not implement the root service, aggregate
reservations or production Paper admission.
