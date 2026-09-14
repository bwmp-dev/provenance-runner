# Retained kernel route observation

After each sealed install/refresh, the native actuator reads its actual retained
routing namespace's nftables ruleset and records a bounded structural identity.
Before renewal it reads back and compares the old installed identity. Drift is
refused, not silently repaired; the owning route then withdraws and disconnects.
No command opens a controller/guest namespace through a mutable PID pathname.

The identity retains rule order, all grants, absolute deadlines, policies, limits,
connection ceilings and kernel object handles. Handles detect replacement of
apparently identical budget objects. Only packet/byte counter values, remaining
address-element TTLs, and valid dynamic connection membership are excluded.
The dynamic member must still use the exact one-key connection-count statement
and ceiling present in the rules. Set enumeration order is normalized, not tuple
or rule-expression order. Duplicate JSON keys, excess nesting, oversized output,
foreign tables, unexpected object kinds and non-drop chains are refused.

`RetainedRoute.ObserveInstalled` rechecks live owned children, exact topology,
protected executable identities and the installed kernel snapshot. The owning
`AuthorityRoute.ObserveInstalled` additionally serializes with refresh/expiry,
requires current authority for the exact original job, and refuses simulated
actuators. Observation failure withdraws that supervisor. Other platforms refuse.

This is not continuous detection of arbitrary privileged host-administrator
actions, proof of a measured rootfs/Sentry launch, a signed record, or a cleanup
claim. The host kernel and trusted controller remain trust boundaries. Runtime
measurement and production provider composition are still required; no network
capability or offer/Paper fence is relaxed. Ruleset readback is bounded to 64 KiB;
an installation exceeding that bound fails closed and is torn down.

Unit tests cover accounting changes versus enforcement changes, recreated handles,
dynamic connection ceilings, reordered sets/rules and malformed output. Disposable
kernel tests add an allow rule and recreate budget objects, proving observation
refusal, failed renewal, route/DNS withdrawal and owned cleanup. Live mapped Sentry
tests read back active and renewed authority while both-family TCP/UDP flows run.
These isolated fixtures do not claim production network-enabled Paper acceptance.
