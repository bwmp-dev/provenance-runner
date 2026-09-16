# Late measured-worker secret composition

Selected-secret metadata may pass signed input preparation, but downloading does
not invoke the secret source. The worker waits for the authenticated root's
sealed observation of the complete original job. Only then can the execution
helper call the trusted gateway source, with live authority checks before and
after acquisition and a delivery expiry bounded by the accepted lease.

Acquisition and redactor installation remain in PREPARING. Only afterwards may
the gateway's start callback commit RUNNING; Java stays behind the closed root
bootstrap gate until that acknowledgement completes. The preparation deadline,
secret expiry and current authority are rechecked after the callback. This
ordering is covered by the real gateway-secret composition fixture.

The worker verifies ordered names and obtains independently owned read-only
sealed descriptors. It builds a fresh collector from the delivered redaction
values while the Java bootstrap gate remains closed, reattaches the live
observer, and closes the old empty collector. It never mutates an active
redactor. The session uses this collector for live output, structured events and
the complete compressed archive before sending release.

Descriptor handles and original memory-file owners remain attached to the
worker session through execution and cleanup. Root independently owns its
materialized tmpfs copy and its cgroup-first retirement. Failed root retirement
continues to fail worker cleanup and drain capacity rather than imply success.

The disposable connected-worker case runs the real non-root provider against
the configured root daemon and verifies one late source call, read-only guest
access, live and complete-archive redaction, opaque terminal evidence and idle
capacity only after retirement. This is a synthetic gateway-source callback,
not a claim that production gateway delivery or real Paper secrets passed.

Protocol advertisement is unchanged and remains disabled for this measured
endpoint. No-network v2 execution, pinned real-Paper image acceptance and host
quota/provisioning remain separate deployment gates.
