# Inactive network-v2 grant validation

This slice consumes the immutable alpha.30 generated Go module and source
vectors already pinned by `network-v2-wire-acceptance.md`. It adds no public
contract, production caller, advertised feature or enabled runtime path.

`NewV2Binder` accepts bounded deterministic bytes of the complete effective
policy and its expected SHA-256. It independently refuses missing, mixed,
unknown-field, unknown-enum, noncanonical and malformed policies. Duplicate wire
fields cannot be repaired into an accepted grant even when their incoming hash
matches. Resources and all three positive timeouts remain part of the checked
identity, not just the networking subset.

Every canonical whole hostname/port/transport tuple and both finite caps must
fit the validated trusted local maximum. Missing or invalid maxima are refused
even for explicit `none`; a mismatch never silently narrows a frozen grant.
The adapter retains exact tuples when constructing the existing binder. Only
trusted local configuration supplies the resolver, sensitive-network inventory
and TTL ceiling. Explicit `none` never resolves a hostname. Accepted state is
copied, so later caller mutation cannot change grants or the deny inventory.

Tests reproduce the released complete-policy bytes, exercise actual synthetic
dual-stack DNS through the binder, preserve tuple/cap identity and refuse
cross-product grants, widening, invalid ports/names, malformed metadata and
noncanonical wire. These are local validation and binder integration tests,
not gateway authentication, five-source authority or installed network evidence.

The disposable DNS fixture also constructs a synthetic complete effective policy
through this adapter before resolving or compiling rules. Actual isolated packet
tests pass dual-stack answers over TCP/UDP, refusal, shared-counter-preserving
refresh, expiry and withdrawal. With the pinned Sentry fixture image
`sha256:c7a58bb86199297bea8bbc9118770c17e2530308ad13d841dc02594e20912bb4`,
the caller-mapped non-root guest passes controlled DNS and unlisted-name denial.
The post-guest lifecycle probes remain separate kernel clients; synthetic full
resource metadata is not a runtime measurement or authenticated platform grant.

The existing gateway offer and Paper adapter continue to reject **all** v2 jobs,
and protocol feature 9 remains unadvertised. Before runtime activation, the
gateway must bind the authenticated effective policy to the actual job/lease and
the same immutable runner maximum. A privileged actuator must own the per-job
network lifecycle, controlled DNS, refresh/withdrawal and cleanup, pass actual
disposable Sentry acceptance, and undergo a separately measured rollout.
