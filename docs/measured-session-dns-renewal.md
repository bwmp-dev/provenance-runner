# Owned session DNS renewal

The measured session constructs its own binder from the frozen complete job
policy plus separately supplied trusted local maximum, sensitive-network
inventory, resolver and TTL ceiling. Initial answers are resolved before child
creation. Callers no longer pass a precomputed list of bindings into the session.
Canonical permissions are grouped by hostname without widening whole tuples.

The same binder is retained for the entire session. Its first complete public
IPv4/IPv6 address set remains pinned; changed answers permanently refuse that
hostname, including after the original answers return. Each complete refresh has
a five-second context bound. The renewal timer runs halfway to the earliest
whole-second DNS deadline used by the kernel, never by extending an old answer's
TTL. Expired or missing bindings are refused.

Successful resolution goes through `AuthorityRoute.RefreshDNS`, preserving the
existing atomic rules update and connection/byte budgets. DNS renewal cannot
extend gateway authority, alter grants, reset traffic limits or revive an
expired/withdrawn route. Any resolution or refresh failure withdraws authority
and triggers whole-session shutdown. The controlled guest DNS server consumes
the same installed binding view as packet enforcement.

Session cleanup cancels the refresh context, withdraws authority, terminates
the workload and retires the existing owners. Completion also requires the
refresh goroutine to finish; a stuck resolver is not reported as released
capacity. Resolver implementations must honor their context and bound answers.

Unit tests cover copied maximum/inventory, immutable address pins, permanent
rebinding refusal, frozen policy identity, expired kernel deadlines and cancelled
resolution. Disposable sessions use a four-second DNS ceiling and must observe
successful renewals during the existing packet/default-resolver checks. A new
upstream-resolution-failure case requires live-session shutdown and full cleanup,
alongside the existing actual listener-loss case. All five session cases run
three times; the bounded fixture timeout accommodates the additional case.

This remains internal controller integration, not an authenticated root RPC,
global identity/resource reservation, production network activation or real
Paper acceptance.
