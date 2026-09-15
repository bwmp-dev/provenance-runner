# Measured network session

The internal controller now has one owner that composes the journaled router,
gated measured workload, private link, journaled host uplink and native firewall.
Its inputs are trusted in-process configuration: an already prepared bundle,
freshly reconciled authority, retained measurement/tools, recovered journals,
fixed distinct router/workload mappings and standard-file descriptors. It is
not a privileged RPC accepting worker-selected paths, commands or identities.

Construction leaves the workload gated. `Release` requires the exact live
uplink, private layout and firewall proofs already enforced by the process
owner. Runtime observations use that same owned process. The session watches
router loss, workload exit, authority withdrawal and controller cancellation.
Router loss therefore triggers withdrawal and whole-workload termination
without waiting for the next DNS renewal or gateway acknowledgement.

Every non-nil construction result owns its partial state, including the bundle
and authority. Cleanup attempts firewall withdrawal first but still attempts
process termination if firewall cleanup fails. It preserves the private link
until native firewall disconnection succeeds, then retires links, uplink,
retained native handles, router and bundle. A failed stage keeps its cleanup
owner for retry. The completion channel closes only after all owned stages
retire; it is not a global capacity or measured-mount proof. The follow-on
[owned DNS channel](owned-router-dns.md) is now included in session teardown.

Normal process completion returns the process result, not a manufactured
authority-loss error. Router loss and other cancellation sources remain
infrastructure failures. Once cleanup starts, launch and runtime observation
cannot resume. The separate process API still permits a caller to freeze
evidence while execution is live; session completion does not invent a final
measurement after the sandbox has exited.

Disposable acceptance adds normal completion, router loss during live traffic
and partial startup failure after process creation. Each case must retire its
bundle and uplink state; normal and router-loss cases execute the same fifteen
packet/confinement assertions as the existing measured fixture. The complete
three-repetition suite retains all prior ownership, authority, cold-recovery
and cleanup requirements. Its bounded timeout increases for these nine added
controller cases, not to excuse a failed case.

Global identity/resource reservations, root service/RPC authentication,
secret/event handoff, Paper composition and hosted egress
acceptance remain separate requirements. Production network-v2 admission is
not enabled by this internal composition.
