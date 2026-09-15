# Journaled host uplink

`HostUplinkJournal` owns at most one private-router uplink in a trusted,
root-private persistent state directory. Opening retains the controller's
current network namespace and protected tool descriptors; recovery is mandatory
before creation. This is not a global job-capacity or identity allocator.

Before any interface mutation, creation writes and synchronizes a canonical
intent containing the boot and host-network identity, random token, complete
lease/attempt binding and policy digest. A private-router veth pair is labeled
before its host endpoint is transferred through a retained namespace descriptor.
No caller-selected host interface, PID, namespace path or address is accepted.

The router's `wan0` uses `10.0.2.1/24` and `fd00:2::1/64`; the generated host
endpoint uses `10.0.2.2/24` and `fd00:2::2/64`. Permanent neighbors bind both
families to the actual opposite MAC. Router defaults use the host endpoint;
host return routes cover only `10.0.1.0/24` and `fd00:1::/64`. Existing host
addresses or routes overlapping either private subnet are refused. This owner
does not enable host forwarding, NAT, DNS or Internet access.

Validation rereads the exact intent, both original link identities, and fixed
address, route and neighbor observations. A mismatch permanently refuses
validation; restoring metadata does not restore authority. Measured launch and
runtime evidence require this opaque owner bound to the exact private link,
router, workload, lease and attempt on both sides of firewall observation.

Warm cleanup deletes only the original router-side pair through its retained
namespace, verifies absence on both sides and of the private host routes, and
retires the intent. Foreign identity or journal contents refuse deletion.
Every non-nil creation result, including a partial failure, must be closed.
The launch owner borrows the uplink; the outer controller owns its cleanup.

Cold recovery must follow process-journal drainage and release of all private
namespace handles. Namespace destruction removes the veth peer and its routes
in the kernel. Recovery never adopts or deletes a surviving host interface: it
waits at most five seconds for an originally labeled peer to disappear, refuses
foreign identity, then retires the intent. A surviving interface after a boot
change is also refused. Recovery cannot reopen a previous execution.

Disposable tests cover real bidirectional IPv4/IPv6 fixture traffic, occupied
slot refusal, altered host alias, corrupted intent, conflicting host prefix,
permanent refusal after restoration, missing-uplink launch rejection and cold
controller exit with durable process/bundle/uplink recovery. Endpoints live
inside a network-none container, so these tests do not claim hosted Internet
egress or production readiness. Production remains gated on controller
composition, host policy, DNS, global reservations and hosted acceptance.
