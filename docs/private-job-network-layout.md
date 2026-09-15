# Fixed private job network layout

The private-link owner configures both endpoints before it can become ready.
The router uses `10.0.1.1/24` and `fd00:1::1/64`; the workload uses
`10.0.1.2/24` and `fd00:1::2/64`. Workload default routes point only to the
router. Both ends have permanent IPv4 and IPv6 neighbors bound to the actual
opposite MAC. Automatic IPv6 link-local generation is disabled on this pair;
the fixed IPv6 addresses use `nodad` because each pair is isolated.

`ValidatePrepared` reads actual kernel address, main-route and neighbor state through
retained protected executables and namespace descriptors. It requires the exact
workload interface inventory and addresses, connected routes and defaults, and
permanent neighbors. Router observations are scoped to the owned interface so
the separately managed uplink can exist. Interface-scoped ip route output omits
the device field; only that scoped router query accepts its omission.

The launch gate requires this prepared-layout proof on both sides of its native
firewall observation. The owner fingerprints validated observations without requesting traffic
counters. Row ordering is canonicalized. Any mismatch permanently refuses
all link validation; restoring state does not reauthorize a launch. Cleanup still uses
the original link identity and can remove an owned pair with damaged routing.

Unit tests reject alternate routes, gateways, interfaces, addresses and mutable
neighbors. Disposable measured tests configure the private network only through
this owner and exercise route deletion, IPv6 address deletion, neighbor deletion,
extra interfaces and refusal to resume after restoration. A separate launch
refusal case deletes the default route while the child is gated, proves no guest
output, restores the route and verifies the gate cannot reopen.

Prepared layout is not a runtime host-address claim. The measured Sentry fixture
shows that runsc removes workload kernel addresses during network-stack handoff,
which also removes associated IPv4 routes and neighbors. Runtime `Validate`
therefore retains the original exact link-identity checks, while the runtime
observation separately verifies the measured Sentry objects and installed native
firewall. It does not incorrectly require the pre-exec kernel address inventory
to survive the handoff, or silently adopt a changed pre-exec layout.

This is not host uplink, forwarding, NAT or DNS provisioning. It does not check
global capacity or grant network permission by itself. Those controls and hosted
acceptance remain required before production activation.
