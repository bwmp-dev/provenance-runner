# Serialized measured controller ownership

The internal controller now owns one admission slot for its provisioned journal
set, from before bundle creation and input copying until verified retirement.
Configuration fixes the root bundle directory, immutable local policy/mappings,
measurement, route tools, resolver and aggregate input-copy ceiling. A start
request contains trusted guest execution, input descriptors, current authority
and standard-file descriptors, not host paths, identities or resource overrides.

Construction verifies the configured root against the retained journal inode,
retains its own measurement reference and claims the bundle journal. Existing
journal file locks provide process exclusion; the controller claim also rejects
another controller or direct bundle admission/recovery/closure in this process.
Recovery drains durably owned cgroups and bundles before checking the host uplink.
Existing active bundles are not adopted.

A start reserves the slot before writing any durable intent. Input staging and
session construction share one original preparation clock; a one-shot budget
claim cannot reset it. Session release starts the execution clock as before.
Every non-nil job result owns partial state, including failures before session
construction. Authority cleanup remains owned and retryable on those failures.

Completion requires authority withdrawal, whole-session and bundle cleanup,
and a successful journal/uplink recovery check. A failed step holds the slot and
remaining handles for retry; neither cancellation nor main-process exit alone
releases it. Retrying cleanup preserves an already completed normal result.
Old job handles cannot operate on a later job. Controller shutdown stops new
admission, drains its active job, closes its retained measurement and finally
releases the in-process journal claim. Callers keep borrowed journals/tools alive
through controller shutdown and close them afterwards.

Disposable normal sessions exercise this controller, including rejection of an
occupied journal, competing controller, bypass admission and a second active
job. Bad input hashes must retire staging ownership before a valid job starts.
A deliberately created unknown journal file makes cleanup fail and must retain
the slot; removing that exact fixture file permits cleanup retry and reopening
the controller. All six controller cases are mandatory in each of three runs,
alongside existing packet, DNS, identity, phase-deadline and recovery checks.

The provisioned identities must still be exclusive to this service on the host.
This does not claim an aggregate host cgroup/disk reservation, root RPC peer
authentication, Paper-specific input/command derivation, secret/event handoff
or production network activation. The guest/input arguments here remain trusted
provider output, not a generic privileged execution API.
