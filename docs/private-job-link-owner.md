# Owned private workload-to-router link

`CreatePrivateJobLink` creates the veth pair and its
[fixed private layout](private-job-network-layout.md) between the exact retained
router and workload namespaces. Both must initially contain only loopback and
have distinct mapped owners. The operation uses retained protected executables
and a passed namespace descriptor for peer transfer, never a PID lookup, shell,
host network interface or workload-selected path.

Creation starts with randomized temporary interface names. The pinned `ip`
implementation ignores the outer veth alias during creation, so a subsequent
operation attaches the full random ownership alias and final name together.
The owner retains namespace descriptors plus both final interface indices, peer
indices, aliases, kinds and MAC addresses. Partial creation retains its generated
temporary names for bounded cleanup; preexisting interfaces are not adopted.

Validation refuses drift permanently. Cleanup is independent of process liveness,
uses the retained namespaces and refuses changed or foreign identities. Restoring
the original identity allows cleanup but cannot revive validation. Cleanup removes
only the owned pair, checks its absence on both sides, then closes retained
descriptors. It does not remove the router's uplink or claim global capacity is
released. Complete cold recovery still requires draining both journaled process
owners and closing every namespace reference; this is not a host-link journal.

`ObserveInstalledForLink` binds the link to the native actuator's exact router
and workload, checks it around policy observation, and withdraws on mismatch.
The measured launch gate and new network runtime observations require this proof.
The process owner borrows the link; outer teardown owns route and link cleanup.

Disposable tests use the actual owned pair for Sentry traffic and verify refusal
to adopt existing interfaces, changed-alias deletion refusal, no revival after
restoration, original-identity cleanup and missing-link launch refusal. The expanded
suite remains bounded at 240 seconds for Go, 250 for its container-side supervisor
and 270 for the outer controller. Host uplink/forwarding/DNS provisioning, global
reservations, root RPC and hosted acceptance remain separate requirements.
