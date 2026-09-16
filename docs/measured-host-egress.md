# Hosted outer egress guard

`scripts/measured-host-egress.py` renders rules; it never installs them, changes
sysctls, rewrites UFW, starts a service or grants a job network authority. The
per-job namespace firewall, authenticated effective policy, controlled DNS and
finite connection/byte/time limits remain mandatory. This additional host guard
exists because the owned uplink intentionally does not configure host NAT or
forwarding.

The closed version-1 JSON plan names `wan`, a canonical public `hostIPv4`, and a
nonempty `sensitiveIPv4` prefix inventory. The host address and conservative
special-purpose IPv4 exclusions are always denied. Interface names and prefixes
are validated before rendering; shell expressions and nftables fragments are
not inputs. Operators must inventory all public management/control-plane ingress
addresses, including proxies, rather than only private origins. A stale inventory
must not be treated as proof that a newly moved management endpoint is excluded.

The `inet provenance_egress` table drops all host input from the root-owned `ph*`
uplinks. Forwarding from those uplinks permits only source `10.0.1.2`, the selected
WAN, non-sensitive IPv4 destinations, and TCP/UDP destination ports 80/443.
Destination-NAT, invalid state, alternate source/interface, SMTP and IPv6 all
refuse. Return traffic must enter from the selected WAN, target the job address,
and be established/related. IPv6 is deliberately unavailable in this initial
host profile, not silently passed through a host lacking an IPv6 uplink.

The separate `ip provenance_egress_nat` table masquerades only that same job
source/interface pair. Other host traffic has no new NAT rule. Neither table
flushes, replaces, edits or accepts on behalf of existing firewall tables.
An accept verdict in this earlier base chain **does not override a later UFW
drop**. UFW therefore also needs narrowly scoped route permissions; never change
its global forward policy to accept. A host dry-run of a route rule using
`in on ph+ out on ens3 from 10.0.1.2` and the exact protocol/ports confirms the
installed UFW supports the required interface prefix. That dry-run is not an
installed rule or an activation proof.

Installation still requires an owned, persistent transaction: fresh interface,
route, firewall, sensitive-inventory and sysctl checks; no pre-existing foreign
table with these names; exact rules/configuration custody; fail-closed boot and
worker dependency ordering; atomic rule loading; narrow UFW route rules; and
verified recovery. Enabling host forwarding affects other interfaces too and
must happen only after the guard and existing default-deny forwarding are
verified. This renderer does not implement or claim that installation. Never
apply its output by flushing the host ruleset or replacing UFW-managed tables.

## Acceptance

The disposable packet fixture begins with a private networkless container and
no existing rules, links or namespaces. It creates synthetic job and WAN peers
and requires reachable baselines before testing denial. Actual packets prove
permitted HTTP/HTTPS and restricted source NAT, host/private/metadata/management
and SMTP denial, source-spoof denial, reachable IPv6 denial, and preservation of
an independent later default-drop forward chain. Permanent IPv6 neighbors model
the production uplink and avoid treating incomplete neighbor discovery as a
successful policy denial. Exact owned links, namespaces, tables and the container
must disappear after a successful test. Failed guests are stopped and retained
by the driver. CI retains exact-head packet evidence.

This is an outer-boundary test, not another full gVisor/Paper execution or live
production activation. It does not prove public IPv6 connectivity, proxy endpoint
inventory completeness, actual UFW persistence across reboot or gateway/database/
object-storage recovery. Those remain coordinated deployment requirements.
