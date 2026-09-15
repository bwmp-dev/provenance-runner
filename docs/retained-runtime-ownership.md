# Independent runtime measurement ownership

`runtimeidentity.Lease.Retain` gives a controller its own close-on-exec
descriptors for the already measured runner, sandbox, SquashFS root, image,
and loop device. It duplicates the retained descriptors, never reopens the
configured paths, and validates the measurement before and after duplication.
Partial failure closes only the newly acquired descriptors.

Each owner must close its own lease. Closing the original does not invalidate
the retained owner; closing an owner permanently prevents its validation or
retention. Validation, retention, and closure on one owner are serialized.
Callers must not copy a Lease value or concurrently close an owner while using
its descriptor paths: retain a separate owner for the full operation instead.

This is descriptor ownership, not execution, network, or cleanup authority.
It neither keeps a mount configured by a trusted administrator immutable nor
proves that sandbox descendants have stopped. Existing measurement validation,
network authorization, resource checks, and whole-job cleanup remain required.
No production provider mode or feature advertisement changes here.

The disposable protected SquashFS fixture checks distinct close-on-exec
descriptors for the same kernel objects, original-owner closure, and concurrent
retention. The measured routed Sentry fixture closes the original owner before
all six real withdrawal/expiry executions and continues using only its retained
copy. Non-Linux platforms continue to fail closed.
