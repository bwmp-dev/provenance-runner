# Root-confirmed network capability

`PROVENANCE_MEASURED_NETWORK_V2=enabled` requires an explicitly configured root
service endpoint and `PROVENANCE_MEASURED_NONE_PROVIDER=isolated`. The connection
must also opt into terminal evidence v2. These settings remain disabled by
default and cannot be supplied by job or connection JSON.

The worker queries its authenticated root endpoint before connecting to the
gateway. A new nonce-bound, descriptor-free exchange returns only the root
controller's public effective-policy maximum. It returns no identities, paths,
credentials, resolver inventory or lease authority. The root confirms the
controller is actually idle and its pinned image and resource controls remain
ready. Responses are canonical closed Protobuf, bounded to 16 KiB plus a
32-byte nonce, and the exchange has one five-second deadline. Non-root peers,
wrong message kinds/nonces, descriptors, EOF, unknown fields and noncanonical
encodings fail closed.

Startup snapshots the verified maximum. Gateway capabilities contain its v2
network policy instead of the legacy network field, and resource capacity is
the intersection of connection settings and root limits. Caller mutations and
returned capability objects cannot modify the snapshot. Network policy and
current-authority features require durable acknowledgements, correlation and
terminal evidence v2 together. Rollback of either the network or evidence opt-in
withdraws network advertisement.

Only the advertised session snapshot may admit a v2 offer. Admission retains all
ordinary checks plus both configuration and root network maxima, root resource
and timeout ceilings, exact hashes and selected-secret metadata. Acceptance
persists the original specification and v2 evidence flag before acknowledgement.
It does not manufacture a current grant. The existing fresh-reconciliation
authority path remains mandatory; stream loss permanently withdraws the attempt.

Existing legacy no-network policies can still use the separate isolated provider
when terminal evidence v2 is selected. Their wire policy is not changed. v1
execution cannot enter the measured dispatch path, and enabled-network failure
never falls back to no-network execution.

## Verification boundaries

Unit/race tests cover startup gates, immutable limits, capacity intersection,
offer persistence, refusals and rollback. A generated gRPC stream fixture checks
that an offer alone never starts its synthetic worker, missing/expired authority
prevents startup, and disconnect withdraws a current grant while retaining the
unsettled journal and cleanup result. That worker does not launch a guest.

The separate disposable root suite adds actual maximum queries after each
retirement plus nine authenticated malformed-response cases. Its prior secret
capability suite took 177.92 seconds for 30 service cases within a 180-second
harness ceiling. The additional exchanges receive a 210-second service/220-second
subprocess ceiling and a 650-second outer ceiling. Individual job deadlines,
resource limits, output bounds and retirement checks are unchanged.

With the twenty-repetition worker stress prelude enabled, the combined outer
ceiling is 870 seconds. This accounts for that separate 220-second test stage;
CI's overall 15-minute job ceiling and every individual job limit are unchanged.

These tests do not establish production provisioning, full gateway-to-Paper
composition or live scheduling acceptance. Those remain activation gates.

### Local integration observations, 2026-09-16

The pre-integration capability worktree passed the complete disposable kernel
suite, including three repetitions of root maximum queries, malformed-response
refusals, secret capability checks and owned resource retirement. Its service
binary was `2cf66576d649fe5fb1ad661a4d7e5756f22eb012855ff0b3717f1d65f048c01f`,
kernel-test binary
`8393c9f529bdf27d8e2730d9d5fa56121727d715578ba6ee2f428511ac1b2e50`,
and synthetic root image
`bfd8b374ede7c1f535cab436d68d68875331eb2efcc35c9eae8cbd377ef98071`.

Three real Paper 1.21.8/build 60 executions also passed with the synthetic
secret fixture, including read-only injection, raw/encoded output redaction and
retirement. That run used the same service binary, worker binary
`d93e17d26cdd8bdb09fb5615eea52185bb5104551aa008b88ed15e28f96bed5d`,
root image `6d0a79fcd156c39a1b362cc4295367989ef72ccbb6a475aad399228b3211c32e`,
and secret target
`b84160a378c4e0eaa5f8ada6b0b05a825791c2baf89d11aff5304bf3f923a4b1`.
These are local build observations, not released binary attestations.

After consolidation onto main `261fae5e730f8c99a36b404ba9bd7038888d7c2f`,
the full Go race suite, vet, four Python acceptance-driver tests and shell syntax
checks passed. Publication remains paused for investigation of main's
intermittent worker CI failure; none of these local passes supersedes that
failed check. Actual isolated no-network-v2 acceptance, full gateway-to-Paper
composition and production activation remain outstanding.

The integration was subsequently rebased onto
`870f3ac1508eec9bb8480371eb80e34c65cbb2a6` (root-completion diagnostics and
twenty-repetition worker CI stress). That main revision's CI and disposable
systemd checks passed. The original intermittent worker failure remains
unexplained and still blocks production activation; successful stress does not
establish a root-cause fix.

The rebased integration passed the full race suite and vet, and three real
Paper executions with secret injection and redaction. The latter used service
binary `e01bb0efb74e118231e7694bca6aeed746460951ab0b9124fc81bdc92a8164a5`
and worker `32ac6d638ec0a07d7419080d674a6a2880be6f8f08ec05878efa66acb4910b71`,
with the same pinned real image and secret target above.

An initial combined stress run completed all twenty worker repetitions but its
subsequent service report exceeded the former 64-KiB harness transcript bound.
That run is not accepted as a full-suite pass. The service report now has a
128-KiB bound and the combined service/recovery report has a 192-KiB bound;
stderr remains 64 KiB. These are test harness transcripts, not guest log limits.
All repetition, refusal, retirement and missing-marker assertions remain required.
