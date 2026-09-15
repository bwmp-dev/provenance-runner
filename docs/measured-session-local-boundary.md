# Fixed local measured-session admission

Session construction now requires an immutable controller provisioning boundary.
It fixes the workload/router host mappings, full local network maximum, resource
ceilings, phase-time ceilings, sensitive-network inventory and DNS TTL. None of
those values are taken from a job-selected host identity or inferred as a local
maximum from the received grant. The constructor copies mutable policy and
inventory inputs.

Admission validates the complete frozen job identity and requires gVisor with
required isolation. CPU, memory, disk, process count and each phase timeout must
fit the local ceiling and the existing provider's hard bounds. Whole network
tuples and connection/byte limits must fit the local network maximum. Phase
durations use the existing whole-millisecond, at-most-one-hour provider contract.
The exact separately provisioned workload and router identities must match.

An overbroad grant is refused; it is never silently clamped or rehashed into a
different job. Refusal happens before session ownership transfer, DNS lookup or
router/workload creation, leaving the prepared bundle with its caller. The
session's DNS binder receives the same copied local network maximum/inventory.
Fresh gateway authority and all existing prepared-bundle/owned-kernel checks
remain separately required.

Unit tests exercise every resource/phase/network ceiling, copied provisioning
state, wrong identities, overflow and invalid configuration. Disposable normal
sessions require resource-maximum and identity refusals to preserve the prepared
bundle and scope, followed by successful ordinary execution under the correct
boundary; each negative case is mandatory in all three repetitions.

This is per-job admission policy, not an aggregate host budget or exclusive
identity reservation. It does not provision identities, implement root RPC,
change production admission, or replace execution deadline supervision.
