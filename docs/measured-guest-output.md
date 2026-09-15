# Measured guest output consumption

The host stream reader enforces one complete finite transcript: separate stdout
and stderr share the job log limit (at most 16 MiB), event bytes have a 4 MiB
aggregate limit, and at most 16,384 frames are accepted. Logs precede events; one
canonical bounded outcome must be last, followed by EOF. Duplicate, missing,
truncated, out-of-order and inconsistent infrastructure claims are refused. The
frame-count bound also limits one-byte-frame CPU and framing overhead abuse.

The evidence collector accepts this stream once into its existing whole-stream
redaction, bounded live projection and complete compressed log pipeline. Redactor
state survives frame boundaries. Stdout cannot become a structured event channel.
Only bounded, newline-terminated JSON from the separate event frames is recorded
as probe input; count, per-event and sanitization failures refuse the transcript.
Failed streams retain sanitized diagnostics and mark the collected event channel
invalid, rather than offering a partial successful lifecycle.

The caller owns cancellation of a blocked reader and must close it or set a
deadline; context checks alone cannot interrupt arbitrary I/O. Live sinks retain
the existing nonblocking requirement. Collected transcripts and their raw event
accessor are untrusted and may contain test secrets: never persist or publish
them. Only the evidence collector's sanitized projections may leave the worker.

This is not runtime identity or completion evidence. The integration must still
independently verify actual process exit, retire every owned sandbox object, run
the Paper lifecycle validator against the exact test plan, and build observed
terminal evidence. The real disposable guest fixture exercises the bounded reader
with synthetic Java, not real Paper compatibility or production activation.
