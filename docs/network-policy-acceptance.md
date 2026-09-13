# Controlled network address-binding foundation

Status: Address-binding and inactive routed-firewall foundations; not production
runtime enforcement or WP-11A acceptance.
The production runner still advertises and enforces `network=none`. This package
has no production caller, production firewall actuator, namespace manager or
capability flag. The owned lifecycle below is exercised by disposable actuators.

## Inputs and ownership

The platform retains ownership of the five-layer permission intersection. This
runner package does not copy that arithmetic or authenticate its sources. Its
internal options require an exact job identifier, explicitly resolved permission
tuples, positive connection/aggregate-byte-rate ceilings, a bounded maximum DNS
lifetime and the operator's nonempty sensitive-network inventory. It cannot infer
a restricted destination profile from an empty allowlist. Missing constraints are
errors. `none` has no permissions, limits, lifetime or DNS; unrestricted is refused.

The sensitive inventory must include all actual management, control-plane,
runner-host and locally translated/routed sensitive prefixes, including public
addresses. Its presence is validated; completeness cannot be inferred by this
library. No deployment may treat a caller-supplied list as authenticated inventory.

Permission tuples preserve hostname, port and TCP/UDP together. IP literals,
numeric aliases, wildcard/noncanonical names, duplicate tuples, SMTP and arbitrary
DNS/DoT ports cannot acquire grants. The closed errors never contain DNS answers,
hostnames, raw transport errors or other caller-provided diagnostics.

## Resolution and binding

The explicit TCP resolver endpoint has no OS resolver, search-domain, environment
proxy, fallback-server or redirect behavior. Five seconds bounds a complete
resolution, including waiting for the per-binder serialization slot. DNS TCP
frames are bounded before body allocation; requests and replies are limited to
4096 bytes. Both A and AAAA must complete successfully before any binding is
returned. A bare NOERROR/NODATA family is allowed; failures are not partial success.

Query ID, response/opcode/truncation/rcode, exact question, record count, class,
type, lengths and complete frame consumption are checked. CNAME chains are
bounded, must terminate in the requested address type, and cannot loop or carry
unrelated answers. Dangling CNAME/NODATA chains currently fail closed, rather than
being treated as a complete negative resolution. This conservative subset is not
a claim of compatibility with every recursive-resolver response form.

Every answer address must pass IPv4/IPv6 special-purpose and operator-sensitive
exclusion; mixed allowed/forbidden answers are refused as a whole. Mapped IPv6 and
standard translation/transition ranges cannot normalize into an alternate grant.
IPv6 is restricted to allocated global unicast with further special-use exclusions.
The implementation conservatively excludes some special-purpose public ranges too.

The first complete, sorted, deduplicated address set is pinned for the job. A
different public set poisons that hostname for the job, even if a later answer
returns to the original set. TTL refresh may renew only the same set. Binding
expiry uses the earliest resolution start plus the minimum answer/CNAME TTL and
explicit configured ceiling; time spent resolving cannot extend that lifetime.
Input and output collections are copied, and bindings expose no mutable backing
storage. Zero, pre-issuance and expired bindings are invalid.

## Acceptance retained locally

- Repeated race-enabled package tests cover policy/hostname/cap validation,
  canonical tuples, no-DNS mode, sensitive IPv4/IPv6 and mixed answers, malformed
  DNS, CNAMEs, minimum TTL, expiration, cancellation, per-job pin isolation and
  concurrent resolution.
- Real ephemeral-loopback TCP fixtures exercise both address families, split
  framing, oversized/zero/truncated frames, partial reads and cancellation.
- A 30-second bounded DNS parser fuzz run completed over 1.1 million executions
  without a failure. This is not a proof that all possible malformed DNS is safe.
- Full runner `go test -race ./...`, `go vet ./...` and the pinned vulnerability
  scanner passed. Focused statement coverage is 92.1%. Module tidying only marks
  the already pinned `golang.org/x/net v0.58.0` as directly used and removes stale
  prior-protocol checksums; no dependency version or protocol pin changes.

## Inactive routed-firewall compiler and kernel fixture

`CompileFirewall` accepts only valid same-job bindings with identical finite
limits. It emits one bounded deterministic nftables batch, never executes it,
and never accepts shell fragments, paths, interface names or table names from
the caller. All tuples retain address, transport and destination port together.
There are at most 128 bindings and 4096 deduplicated packet tuples. Connection
and byte-rate ceilings outside the supported positive uint32 range fail closed.

The target is a **dedicated per-job routing namespace**, with exactly the trusted
`job0` and `wan0` veth links, fixed job addresses `10.0.1.2`/`fd00:1::2`, and no alternate route, workloads, control-plane
services or pre-existing policy. It is not the workload's OUTPUT hook. gVisor
emits raw L2 traffic, so filtering ordinary local process traffic would miss the
relevant path. Input/output/forward default to drop. Forwarding accepts only
original-direction exact grants and established reverse-direction replies to
those grants; there is no unconditional established/related bypass.
Original packets must carry the exact job source address, and replies must target
it; raw address spoofing cannot acquire a forwarded grant.

One constant-key connection-count set covers both address families. One named
byte-rate limit covers both families and directions. Explicit zero **additional**
burst gives nftables a one-second byte bucket; it does not promise a zero-burst
instantaneous rate. Shared accepted-byte and rate-denial counters are available
for future accounting integration, not yet wired to job usage records.

The earliest binding expires the complete snapshot. Absolute Unix-second expiry
rounds down and precedes every acceptance rule, so ordinary installation delay
does not extend grants. Set-element kernel timeouts provide a second, relative
lifetime bound. A future actuator must still reject stale snapshots immediately
before installation, withdraw rules on failed DNS refresh or clock anomalies,
and replace snapshots atomically. Never delete a live table and then install its
replacement: default acceptance during that gap would be unsafe. Teardown must
disconnect the job before deleting its exact table and namespace. The compiler's
delete program names only its owned table and never flushes a host ruleset.

`Firewall.Refresh` now emits one atomic renewal batch for the same still-live
job, address/transport/port grants and finite limits. It flushes only the forward
chain's rules and replaces only the short-lived allowed sets in that transaction.
The base chains keep default drop, while named counters, the byte bucket and
the shared connection-count set survive. Recreating a table or limiter during
renewal would replenish the job's traffic allowance and is deliberately refused.
Zero/future-issued/expired snapshots, changed grants/limits and non-advancing
expiry fail closed. This is renewal, not authorization for a new or changed grant.

`Firewall.Withdraw` removes every forwarding rule while retaining default-drop
base chains and accounting objects. It blocks established replies as well as new
flows. The future trusted actuator must own the installed-snapshot compare-and-
swap, submit the complete batch in one nft invocation, record withdrawal as a
terminal lifecycle state, and disconnect before removal. A copied old snapshot
must never act as permission to resume a withdrawn job. Failed DNS refresh and
unknown command acknowledgements still require explicit denial/recovery; these
program generators do not supply that production orchestration.

The disposable kernel fixture additionally passed atomic renewal with live
dual-stack connections, preservation of their shared connection ceiling,
rollback of an invalid atomic batch, retained counters and byte allowance across
renewal, and withdrawal of established/new TCP/UDP traffic. The bandwidth check
reuses the same two UDP tuples before and after renewal so an exhausted
connection ceiling cannot masquerade as rate enforcement. One local run
forwarded 79,916 bytes over 0.408 seconds spanning renewal, within the original
65,536-byte bucket plus elapsed refill; it did not receive a second fresh bucket.

The trusted fixture creates job/router/fake-WAN namespaces inside one fresh
Docker container with `--network none`, no mounts, no published ports and no
Docker socket. Synthetic public and sensitive IPs exist only on the fake peer;
they do not contact those real endpoints. NET_ADMIN/SYS_ADMIN/NET_RAW and relaxed
container syscall/mount restrictions apply only to this disposable test process.
The outer host and production/personal servers are not configured by the fixture.

Run the repeatable fixture using an exact locally built image ID:

```sh
docker build --iidfile /tmp/provenance-network-fixture-image.txt \
  -f scripts/network-policy/Dockerfile scripts/network-policy
python3 -B scripts/network-policy/acceptance.py \
  --image "$(< /tmp/provenance-network-fixture-image.txt)"
```

Local kernel acceptance passed whole IPv4/IPv6 tuples, reachable-but-unbound
public/metadata/management denial, shared dual-stack concurrent connections,
raw AF_PACKET enforcement, aggregate byte limiting, established/new flow expiry,
and zero remaining owned tables/namespaces. Every denial endpoint is first
proved reachable without policy. Full runner race tests also passed. The owning
`Disposable network policy` workflow retains exact-head source/image/log evidence.
This is a trusted synthetic packet fixture, not the complete malicious-plugin
or production security acceptance suite.

## Caller-configured user-namespace Sentry fixture

The optional `--sentry` fixture additionally executes the pinned 2026-08-30
gVisor build through the isolated router. Its archive checksum is verified during
the `Dockerfile.sentry` build. A trusted outer controller creates a user/network/
mount namespace with exactly two non-root host UID/GID mappings: namespace 0 to
65532 and namespace 65534 to 65533. Before attaching its veth, the fixture checks
the paused child has host UID/GID 65532, no supplementary groups, and those exact
maps. The guest probe itself runs as UID/GID 65532 with empty capabilities and a
read-only static root filesystem.

This follows gVisor's [caller-configured user-namespace method](https://gvisor.dev/docs/user_guide/rootless/).
The pinned build refuses its built-in `--rootless=true` mode with sandbox
networking. Here `--rootless=false` runs **inside the already mapped namespace**;
it does not make Sentry host root. The outer fixture controller is still trusted
root. This is not a fully rootless control plane and must not be translated into
a production flag change. Production's single-ID measured launcher and
`network=none` guard are unchanged; a reviewed privilege-separated namespace
handoff and new measurements remain necessary.

```sh
docker build --iidfile /tmp/provenance-sentry-network-image.txt \
  -f scripts/network-policy/Dockerfile.sentry scripts/network-policy
python3 -B scripts/network-policy/acceptance.py --sentry \
  --image "$(< /tmp/provenance-sentry-network-image.txt)"
```

Local actual-Sentry acceptance passed TCP and UDP over both address families,
unbound public destinations, metadata, wrong-port and wrong-protocol denial,
plus the non-root guest check. The same run first exercises the kernel packet
cap/expiry/spoofing checks. The workflow retains both logs and exact image IDs.
The guest now also retains four real TCP/UDP sockets across atomic renewal and
withdrawal. Both address families must continue on the same established flows
after renewal, then deny both established and new flows after withdrawal. These
guest phases do not restore host interface addresses or restart Sentry. This
packet fixture uses the compiled atomic batches; the DNS fixture below separately
exercises the shared owned-route controller.
This mode adds SETUID/SETGID/CHOWN/SYS_PTRACE only to the disposable controller,
bounded to 512 MiB, one CPU and 256 PIDs. It still has no host mounts, network,
ports or Docker socket. It does not exercise production policy authentication,
DNS delivery, refresh/teardown orchestration or hostile plugin behavior.

## Remaining enforcement gate

A binding is evidence of resolution, not network permission. The future trusted
actuator must bind it to the exact admitted job, withdraw old rules on failed
refresh, install per-job namespace/firewall controls and finite traffic/connection
limits, account for both address families, and guarantee expiry and job cleanup.
It must deny unbound/direct-IP destinations; production still installs no packet
rules from this package. Resolved public IPs can be shared by
multiple names; address binding alone is not an application-layer hostname check.

Authenticated policy loading, the coordinated wire representation for protocols
and bandwidth, the privileged namespace/firewall actuator, controlled workload
DNS service, gVisor/measured-runtime wiring, disposable hostile integration tests
and production activation remain required. They
must not be replaced by successful library tests or by host-side download SSRF
checks. Existing network-disabled execution and artifact-transfer boundaries are
unchanged.

## Primary references

The conservative address exclusions were checked against the
[IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).
The future runtime integration must preserve gVisor's isolated networking model;
its [networking documentation](https://gvisor.dev/docs/user_guide/networking/)
distinguishes sandbox networking from host-stack passthrough. No passthrough mode
is enabled or authorized by this foundation.

Firewall syntax follows the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).
The byte bucket semantics were checked against Linux's
[nft_limit implementation](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_limit.c).
## Prepared workload DNS responses

`WorkloadDNS` is a bounded responder over one immutable job binding snapshot,
not a recursive resolver or an installed network service. Its constructor checks
the same owned snapshot as the firewall compiler. A future actuator must publish
it only after that exact firewall is installed, withdraw it before cleanup, and
replace it only after a successful refresh that preserves traffic counters.
No production caller, listener, namespace or firewall rule is enabled here.

The responder never resolves a name on demand, follows a workload CNAME, accepts
resolver overrides or grants an unlisted hostname. It answers only one IN A/AAAA
question using already-bound addresses. All answers expire at the entire
snapshot's earliest kernel-rounded deadline. Backward time, expiry and permanent
withdrawal stop answers. Unsupported envelopes are refused; UDP responses are
bounded to 512 bytes and TCP to 4096, with truncation instead of amplification.

Tests cover both families, case-insensitive DNS questions, exact binding scope,
kernel deadline rounding, immutable copies, malformed/trailing/oversized queries,
bounded truncation and concurrent withdrawal. A bounded parser fuzz target is
included. Numeric-address alternatives now use lexical matching rather than
machine-width integer conversion, preventing oversized hex labels from evading
the existing no-IP policy. Socket admission, actual controlled DNS packet paths,
firewall publication/refresh coupling and mapped-Sentry acceptance remain pending.

## Owned DNS transport

The transport follow-on adds `ServeOwnedDNS` over already-open UDP/TCP sockets
supplied by the trusted actuator. It does not call Listen, enter a namespace or
infer isolation from an IP address. The actuator remains responsible for exact
namespace ownership and successful firewall installation before exposure.
Validation requires matching non-wildcard endpoints and an explicit bounded list
of exact job peer addresses. Invalid arguments leave socket ownership with the
caller; successful admission transfers ownership to the server.

UDP/TCP share a finite 64-request/second-window admission budget. TCP additionally
allows at most eight active connections, one query per connection and a one-second
read/write deadline. Oversized frames are rejected before payload allocation.
Cancellation or failure of either socket loop permanently withdraws the DNS view,
closes both listeners and all active connections, and joins the workers before
returning. No log or error reflects query contents or upstream credentials.

Unprivileged real loopback tests exercise UDP/TCP responses, exact peer refusal,
oversized TCP framing, a partial frame during cancellation, shared response
limits and post-cancellation withdrawal. They prove transport behavior only;
actual namespace/firewall coupling and Sentry workload traffic are not yet proven.

## Disposable controlled DNS packet acceptance

`CompileFirewallWithDNS` is an explicit variant; the original compiler remains
unchanged. It adds only job0 traffic from 10.0.1.2 to 10.0.1.1:53 over UDP/TCP and
tracked replies. Workload DNS can return either address family through that
single controlled endpoint. It opens no arbitrary resolver or management port.
Input, output and forwarding share the same finite byte and connection objects.
Refresh replaces all three rule chains atomically while retaining those objects;
withdrawal empties all three chains and preserves their default-drop policies.

`scripts/network-policy/dns_acceptance.py` runs actual query packets in newly
created no-network containers, with no host mounts, published ports, Docker socket
or production access. A fixture-only controller refuses the container's initial
network namespace, installs the compiled firewall before starting DNS, and
coordinates refresh/withdrawal. Both A/AAAA answers over UDP/TCP, unknown names,
unsupported types, a previously reachable non-DNS port and spoofed source are
tested. The test checks preserved shared counters, answers past the old deadline
after renewal, denial at the new kernel deadline, all-chain withdrawal, refused
resume and exact table cleanup. Two fresh containers separate expiry and
withdrawal scenarios. The pinned existing Alpine fixture image is reused.

Local disposable packet acceptance passed both scenarios on 2026-09-13. CI now
retains its output alongside the existing routed-packet and mapped-Sentry tests.
This is actual kernel/DNS fixture evidence, not production actuator integration
or proof of DNS from inside the Sentry workload. The following fixture covers
that separate boundary; production integration remains required before activation.

## Non-root Sentry controlled DNS acceptance

The disposable DNS fixture also runs the pinned Sentry in a verified caller-mapped
network/user namespace. Its UID/EUID 65532 guest uses Go's standard resolver against
the owned DNS endpoint and checks exact A and AAAA bindings over UDP and TCP, plus
denial of unlisted names on both transports. The responder accepts only an empty
EDNS0 capacity advertisement (512–4096); options, flags, versions, duplicate OPTs,
and arbitrary additional records remain rejected. UDP answers remain bounded to
512 bytes regardless of that advertisement.

The same live guest remains running across a controller renewal and withdrawal.
It must resolve both families on both transports after renewal, and must lose all
four paths after withdrawal. The controller retains shared counters and refuses
subsequent renewal permanently, then removes its table only after the job route
is disconnected. No host address restoration substitutes for the live guest.
The separate non-Sentry run retains unsupported-type, spoofed-peer, other-port,
kernel expiry and namespace/table cleanup probes.
The Sentry case uses a bounded 30-second snapshot; the separate kernel expiry case
continues to use eight seconds. Neither fixture installs a production actuator,
advertises runner feature 9, nor enables production networking.

Run `scripts/network-policy/dns_acceptance.py --image <verified-image-sha> --sentry`
with the image built from `scripts/network-policy/Dockerfile.sentry`. CI retains
the separate `sentry-dns-acceptance.log` alongside the exact source/image evidence.

## Owned route lifecycle composition

`internal/networkpolicy.RouteSession` now owns the serialized install/renew/
withdraw/close lifecycle behind a trusted, exclusively owned namespace actuator.
Only a successful atomic firewall installation publishes a DNS view. Renewal
invalidates the old view before replacing rules, preserves counter/connection/
bandwidth objects, and cannot resume a withdrawn session. Invalid renewal,
actuator failure, owner cancellation and expiry withdraw the session. Parent
cancellation also interrupts an in-flight renewal using another call context.

Withdrawal attempts default-drop and independent route disconnection even if one
operation fails. Cleanup never removes the default-drop table before successful
disconnection, and failed cleanup retains a retryable owner. Operation errors are
bounded categories rather than command output. The absolute kernel deadline
continues to apply if the userspace observer dies. DNS listener ownership and
failure propagation remain the actuator caller's responsibility.

The disposable DNS fixture uses this same lifecycle with actual atomic nft
transactions and an actual job-facing link shutdown. Its packet acceptance checks
both kernel deadline renewal and irreversible withdrawal, retained counters, and
that the owned route is down when the table is removed. Mock fault/concurrency
tests are not substituted for those packet checks.

This does not expose a production privileged endpoint or establish ownership of
an arbitrary namespace. The production namespace helper, mapped-Sentry/provider
composition, authenticated withdrawal propagation and measured activation remain
required. Gateway/Paper network-v2 refusal and none-only runtime claims remain
unchanged; no full WP-11A acceptance is claimed by this library/fixture change.

## Retained child namespace ownership

`RetainMappedChild` is an internal Linux boundary for the trusted controller's
own direct, living child. It opens a pidfd before procfs access, retains the exact
network/user namespace descriptors, and verifies kernel namespace types and
ownership. The network namespace must belong to that child's mapped user
namespace, whose parent must be the controller's user namespace. Neither may be
the controller's own namespace. Current parent, all real/effective/saved/fs user
and group IDs, two exact one-ID mappings, empty supplementary groups and denied
setgroups are rechecked, along with pidfd liveness, on validation and duplication.

Only an exact matching job handle can duplicate the retained network object;
mutable namespace names or arbitrary caller paths are not accepted. Closing the
handle releases references only, not a claim that a workload or route stopped.
The caller still owns the process and route teardown, and must recheck current
authority before attaching any route. Trusted mapping/job inputs do not replace
authenticated policy, child creation, provider handoff or runtime measurement.

The explicit disposable kernel fixture exercises retained-object identity,
exited-child refusal, wrong job/mapping and supplementary-group refusal, inherited-controller namespace
refusal, a grandchild with a foreign direct parent, descriptor cleanup after
repeated refused captures, and close-without-workload-kill. Every case must pass
three times; skipped kernel tests cannot count as acceptance. Ordinary local
unit/race runs keep the privileged fixture disabled. CI retains the separate
`namespace-acceptance.log` from `scripts/network-policy/namespace_acceptance.py`.
No production namespace API, capability advertisement or network activation is
introduced by this identity slice.

Both live Sentry fixtures now create their child through the disposable
`owned-sentry` controller using this same retained-object boundary. The outer
fixture bind-mounts the retained descriptor and compares its device/inode; it no
longer adopts the child namespace by a mutable PID pathname. The controller
rechecks the live child before releasing the start barrier. Its group drop uses
Go's all-thread syscall wrapper so fork identity cannot depend on the scheduler
thread. iproute2's namespace mount directory is initialized before the retained
bind to avoid recursively stacked mounts during later namespace creation.
These fixtures still have no ambient network, host mounts or production inputs.
