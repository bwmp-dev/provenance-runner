# Current authority consumer foundation (IFC-030)

Protocol inputs are the published and independently verified toolkit alpha34,
source `0975f9931a40d6f8586fb67b6fd2f1da543d899a`, annotated tag
`a6fe4a7c8257fe0f844ec427a2d13bafee77795f`. The Go module is pinned to
`v0.0.0-20260914002628-0975f9931a40` with its module checksum. All ten published
assets passed exact-source/signer-workflow attestation verification, and all
seven archives passed isolated consumer tests before adoption.

`scripts/import-network-authority.py` checks runner archive SHA-256
`0fb88e5ee81b152f9592206fe5d4fd2f05b76896e64506cf840b899e2724e851` before copying
the exact released semantics and vectors. Their SHA-256 values are
`6921ede633c391ae979dd75a70be8f811bf1d6f3dcc279fb3e2e561a2f9bacb9` and
`dd0ebd7347d3b8e4a28b3b22a24618d0c40ee208c955a665a21325d3825096af` respectively.

`networkpolicy.Authority` validates and copies the full original exclusive policy
identity and exact job/lease/attempt. Construction grants nothing. Every incoming
observation requires separately authenticated stream features and credential
expiry. Feature 10 requires 1/3/9; unknown/duplicate features, malformed metadata,
changed identity and invalid bounds irreversibly withdraw the attempt.

STALE disposition is not revocation. Older positive checks cannot extend the
deadline; equal check times require equal expiry. A newer independently acknowledged
lease expiry is retained even when its current-authority check is older. Thus an
old expired lease receipt cannot invalidate a settled renewal. Fresh checks may
extend or shorten only still-live authority; expiry/withdrawal never resumes.
Terminal/cancelling work withdraws; none/offered work receives no new authority.

`ConstrainBindings` requires the complete original host/transport/port grants and
exact caps, copies already validated DNS bindings, and caps their expiry by current
authority. It never substitutes or repairs the policy. Failed binding validation
withdraws authority. This is not installation, a route timer, or a cleanup claim.

Tests use released wire/digest vectors, malformed/unknown fields, dependency and
identity changes, time bounds, stale-receipt ordering, deadline reduction, explicit
withdrawal, expiry, none/terminal cases, copied bindings and concurrent withdrawal.
All tests in this foundation are ordinary unit tests, not hostile workload runs.

Production offer/Paper admission and capability advertisement remain fenced for
all versioned network jobs. This foundation must still be coupled to the owning
route/DNS lifetime and gateway worker supervisor before advertisement. Production
helper/provider, measured runtime identity, hosted acceptance and controlled
rollout are separate remaining gates. No deployment or networking activation is
performed by this change.
