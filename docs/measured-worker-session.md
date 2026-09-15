# Measured worker session

`measuredclient.Run` owns one authenticated root control channel from input
transfer through completion. It verifies the kernel-reported root peer before
transferring private input descriptors, checks the exact job against live
authority, and uses the preparation deadline captured before downloads. Input
transfer and startup cannot restart that budget.

The authority forwarder serializes acknowledgements and the one-shot release on
the same sequence. Root starts the fixed helper and observes its runtime while
the helper is blocked waiting for configuration. Only after importing that
exact-job observation does the worker invoke its trusted pre-release callback.
Root supplies configuration only after an empty, correctly phased release
packet; early, malformed, or duplicate wire releases terminate the session.

Output passes through the existing bounded guest framing and redacting evidence
collector. A successful session result requires an authenticated root retirement
receipt, agreement with the guest's claimed exit, and a still-active deadline.
Neither JSON nor a partial transcript constructs this result. The caller still
must validate Paper lifecycle events and classify compatibility; this generic
transport does neither.

Cancellation joins the local authority writer and closes the channel. This is
not proof of root retirement. Failed sessions return no successful result, and
the caller may retain only redacted diagnostics. Production integration still
needs a distinct failed-session retirement path before it can safely release
worker capacity after cancellation or malformed output.

Disposable acceptance runs three repetitions each of successful execution with
live authority renewal, withdrawal after synthetic Java begins, and rejection by
the pre-release callback before Java begins. The successful case checks redacted
output and structured events. Synthetic padding advances the redactor's secret
holdback window before the live-start marker is inspected; redaction itself is
unchanged. Each root case checks controller, bundle, and journal retirement.

These tests use a fixed synthetic Java stand-in, not actual Paper. This change
does not provision a daemon, connect the production worker, enable measured test
secrets, or activate production network-policy v2.
