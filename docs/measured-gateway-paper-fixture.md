# Measured gateway to real Paper fixture

`scripts/network-policy/paper_acceptance.py --gateway` connects the production
gateway client and Paper provider through generated gRPC to a fixture server.
Execution uses the real privileged root service, measured image, and gVisor
inside the existing disposable network-none container. It runs three times and
requires all ordinary root/journal/loop retirement markers plus three terminal
gateway acceptance markers. Missing or duplicate markers fail the driver tests.

The offer uses the actual root-confirmed maximum and pinned image. Its gateway
identity and download expiry satisfy the same unmodified production admission
checks as real offers. The test server acknowledges durable events only; live
logs and usage are observations. Accepted/preparing/running acknowledgements and
heartbeats supply fresh bounded authority, and terminal acknowledgements contain
no continuing grant. Successful completion requires validated frozen v2 evidence,
one execution, confirmed cleanup, and an empty durable active/pending journal.

This is **not** platform database, object-storage upload, or deployed scheduling
acceptance. The gRPC transport is in-memory; no production credential is loaded.
`--gateway --secrets` additionally requires a root-confirmed secret capability,
one exact selected delivery while still PREPARING, and raw/base64 redaction in
live gateway batches, the worker result and the complete compressed archive.
The archived-log check runs before archive ownership passes to the gateway;
it does not stand in for object-storage acceptance. The intermittent synthetic
worker failure is not claimed fixed by these passes.

## Local observation, 2026-09-16

Three real Paper 1.21.8/build 60 runs passed (66.22, 64.50 and 67.49 seconds),
including refreshed authority during execution, terminal acknowledgement and
all owned resource retirement. Service binary:
`6913ab583fca739379c50801f2df49177ae84e650b85b7dea0f6b04d8982abaa`;
worker binary:
`7e3c5de38900833fe4dd87c79c655559b2edc1599102bdcc51844c5adf43a320`.
The pinned image was
`6d0a79fcd156c39a1b362cc4295367989ef72ccbb6a475aad399228b3211c32e`.
The Paper, gateway and root-service race tests and four Python driver tests passed.

Initial fixture attempts were correctly refused for distinct job/execution IDs,
equal rather than strictly later download expiry, and acknowledgement of a
nondurable live event. Those fixture-server mistakes were corrected without
relaxing production validation. No production service was changed by these tests.

### Secret ordering regression

The first three gateway-secret executions failed before Java startup: the
measured client called the gateway's start acknowledgement before fetching
secrets. That acknowledgement commits RUNNING, while the gateway client
intentionally permits secret acquisition only during PREPARING. Separate
standalone-worker and plain-gateway tests had not exercised this composition.

The measured client now obtains secrets only after authenticated root observation
and current authority, installs the redactor and delivers sealed descriptors
while PREPARING, then obtains the start acknowledgement before releasing Java.
The preparation deadline covers this entire sequence. Expiry and authority are
checked both before and after the acknowledgement; root independently checks
them at bootstrap. Missing or expired secret delivery must not call the start
callback. Regression tests cover expiry, withdrawal, cancellation and refusal
during acknowledgement. No gateway phase restriction was widened.

After that ordering correction, three real gateway-secret executions passed
(54.84, 55.14 and 52.60 seconds), including terminal ACK and all retirement
markers. Service binary:
`c4b78aaf1d036bc5ec1c8307d0679c79cd09982c18ecae6f127b7238703e8b86`;
worker binary:
`7fbad2afae3b83071b4ff4524a97f23d9743996ab536c0968320917b662946d6`.
They used the pinned real image above and the synthetic secret target
`b84160a378c4e0eaa5f8ada6b0b05a825791c2baf89d11aff5304bf3f923a4b1`.
These are local observations, not production or released artifact attestations.

The initial integration CI run `35144843411` also exposed an obsolete systemd
driver mock: it emitted argv but not the newly required NONE-v2 pass markers.
The mock now emits both expected markers and separately verifies that omitting
either fails. Actual systemd/NONE-v2 acceptance still must pass; correcting the
mock does not stand in for that check.

At integration head `c523763d921742537ba725e5fd0f238f77a3085b`, actual
measured systemd acceptance in CI `35148068536` passed both NONE-v2 variants
and cleanup. Its later routed service stage still reproduced the intermittent
failure (worker secrets, exit 137 without OOM), so the overall check failed and
is not waived. A separate three-run real gateway-secret acceptance passed at
that head with service binary
`1592368a50d859351405aa3a1de44af47695b23c1d30b7b21982f92689b34064`
and worker binary
`889df3075f640d4fffb545273cd040e23a11da4a8030b6fab6e19b24beef7807`.
