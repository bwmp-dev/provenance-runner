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
The fixture currently covers plain Paper only and explicitly refuses the
`--gateway --secrets` combination. Independent real secret-injection/redaction
acceptance remains separate. The intermittent synthetic worker failure is not
claimed fixed by these passes.

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
