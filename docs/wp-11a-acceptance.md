# WP-11A network-policy acceptance

This record maps the complete hosted network-enforcement work package to its
owning implementation and acceptance checks. Earlier foundation documents retain
their historical limitations; they do not describe missing current callers.
The program ledger decides package status after exact-head and post-main CI.

## Policy semantics

The platform authenticates and freezes all five inputs: platform maximum,
connection-bound runner maximum, organization policy, project policy and job
request. Whole hostname/port/transport tuples intersect and both finite limits
take the minimum. The first lease and immutable source/job binding commit
together. Replay preserves that original grant and independently checks current
authority; broader later sources cannot enlarge it and withdrawal cannot resume
it. The runner checks the complete released policy identity and its trusted local
maximum before any DNS or packet permission.

`none` grants neither traffic nor DNS. `restricted` requires an explicit bounded
administrator destination profile; `allowlist` further constrains declared
tuples. Neither mode grants arbitrary public access. The released v2 contract
has no unrestricted representation: unrestricted remains reserved for a separate
explicit self-hosted administrator policy and is rejected by this implementation,
including self-hosted callers. This acceptance does not claim unrestricted
self-hosted execution support or add a hosted escape hatch.

## Requirement and evidence map

| Requirement | Implementation and mandatory evidence |
| --- | --- |
| Five-source intersection and authenticated immutable identity | Platform `internal/networkpolicy` policy/source/binding tests; `internal/gateway` normal worker/offer, replay, reconnect, heartbeat and terminal PostgreSQL integration tests. Runner `wire_v2_test.go`, `authority_test.go` and `authority_route_test.go` refuse malformed, broadened, stale, unnegotiated and withdrawn authority. |
| None, restricted and allowlist | None wire tests require zero DNS calls. Actual measured NONE-v2 CI exercises normal and secret-enabled execution. `route_sentry_linux_test.go` executes both enabled modes with actual non-root gVisor TCP/UDP IPv4/IPv6 traffic, renewal and irreversible withdrawal/expiry, three times per case. The driver refuses missing, duplicate, skipped or failed cases. |
| Private, loopback, link-local, metadata and sensitive-address exclusion | `TestSensitiveAddressesCannotAcquireBinding` tests both enabled modes, including mixed answers, mapped/translated IPv6 and operator-sensitive public IPv4/IPv6 prefixes. `TestInvalidPolicyHasNoPermissiveDefaults` refuses SMTP, arbitrary DNS/DoT, invalid names and missing finite constraints. Disposable packet fixtures prove reachable metadata/management and unsupported tuple denial, raw L2 enforcement and source-spoof refusal. |
| Controlled DNS and per-job namespace/nftables ownership | TCP upstream DNS has bounded parsing and no system-resolver/proxy fallback. Workload UDP/TCP DNS serves only the installed snapshot. `dns_acceptance.py` runs real DNS packets and actual Sentry; `namespace_acceptance.py` verifies retained child identity, kernel rules and owned cleanup. |
| Rebinding, expiry, dual-stack limits | Binding tests permanently reject a changed address set. Disposable packet fixtures enforce one shared dual-stack connection count and bidirectional byte bucket, deny excess traffic, preserve live budgets/counters across atomic renewal, and refuse established and new flows after expiry or withdrawal. `measured_acceptance.py` exercises actual measured Sentry, DNS loss/refresh failure, authority expiry/withdrawal, wrong-child observation, launch refusal and durable cleanup. |

The production host's additional outer guard is stricter than the per-job
policy: IPv4 TCP 80/443 only, with hosted IPv6 denied. Disposable fixtures prove
both IPv4/IPv6 per-job enforcement; they do not imply live public IPv6 reachability.
Sensitive-network inventories remain trusted operator input and must include
public management/proxy endpoints as well as private ranges. Address-bound policy
does not provide application-layer hostname isolation between names sharing an IP.

## Retained composed and deployed evidence

- Runner source `e189df5c9691fbf397fe653806706c51b1a83808` passed
  [main CI 35484553581](https://github.com/bwmp-dev/provenance-runner/actions/runs/35484553581)
  and [packet/Sentry CI 35484553587](https://github.com/bwmp-dev/provenance-runner/actions/runs/35484553587).
  The retained `measured-route` artifact contains three successful repetitions of
  every required measured case, twenty worker stress repetitions and explicit
  image-loop, namespace, scope, bundle and journal retirement observations.
- Platform source `15fe7e907e3fde8c2094b6ce17607a315164fa15` passed
  [CI 35477314507](https://github.com/bwmp-dev/provenance-platform/actions/runs/35477314507)
  and [Plan 04 acceptance 35477314505](https://github.com/bwmp-dev/provenance-platform/actions/runs/35477314505).
  Its real worker/inspector/signed-download and PostgreSQL source/lease tests are
  distinct from runner packet enforcement; neither substitutes for the other.
- The private program retains the
  [September 20 deployed recovery and paired pilot receipt](https://github.com/bwmp-dev/provenance-program/blob/086413c304f42327117ef054b1419e30f83991b6/docs/program/evidence/uplink-recovery-20260920.json).
  The same accepted real Paper plugin JAR and fixed endpoint passed once with
  measured allowlist evidence and HTTPS success, and once with measured none
  evidence and unreachable output. Complete stored log digests matched, owned
  resources retired, and no external publication occurred. Earlier failures
  remain retained. This is bounded live acceptance, not a production attack run.

## Restricted-mode completion

The completion adds explicit restricted-mode native Sentry withdrawal and expiry
cases and repeats every sensitive-address resolution denial in both enabled
modes. It changes acceptance coverage and documentation only. No runtime rule,
limit, TTL, authority boundary or production configuration changes.

Reproduce the live native checks in the disposable fixture only:

```sh
docker build --iidfile /tmp/wp11a-sentry-image.txt \
  -f scripts/network-policy/Dockerfile.sentry scripts/network-policy
python3 -B -m unittest scripts/test_namespace_acceptance.py
python3 -B scripts/network-policy/namespace_acceptance.py --sentry \
  --image "$(cat /tmp/wp11a-sentry-image.txt)"
```

Full Go race tests, vet, the pinned vulnerability scanner and all required CI
remain mandatory. Ordinary unit tests skip privileged fixtures and therefore do
not constitute packet acceptance. This record does not close the broader Plan 11
security review, deployment/recovery, product or operations gates.
