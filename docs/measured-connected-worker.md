# Measured connected worker

The trusted `PROVENANCE_MEASURED_SERVICE_SOCKET` setting selects a separate
connected-worker composition. It creates only quota-bounded download caches and
an instance lock, verifies a fresh root-authenticated idle barrier, and does not
construct or reconcile an in-process sandbox. The worker needs the signed Paper
runtime source and artifact-host policy. Root image, cgroup, routing, identity
and journal provisioning remain with the separate root daemon.

The endpoint cannot come from a job. A configured worker refuses legacy
execution and has no fallback if measured execution fails. Local admission is
serialized. It does not advertise test-secret support: measured secret delivery
is still unimplemented and jobs containing secret requirements are refused.

For a separately admitted v2 job, the worker preserves its original complete
specification and terminal context. Preparation starts before manifest and
artifact downloads; the same deadline crosses the root-session handoff. The
root peer is authenticated before file descriptors are sent. Root observation
precedes the gateway execution-start callback, which must succeed before Java
is released. Authority withdrawal cancels the session independently.

The existing bounded evidence collector receives the guest stream, owns the
complete gzip log and emits sanitized live batches. The existing Paper lifecycle
validator classifies probe events; a successful process exit is not sufficient
for plugin compatibility. The original sealed root observation reaches terminal
evidence without JSON reconstruction or a substituted runtime label.

Every owned session is collected and cleaned up, including cancellation and
preparation failure. An authenticated completion can establish retirement even
when event collection failed. Otherwise, after the local session and authority
writer have stopped, cleanup uses fresh root connections to confirm idle state
within a detached 15-second budget. This never renews execution authority. If
retirement cannot be confirmed, both the worker and gateway stop admitting jobs.
Startup must pass root recovery and the idle check before a new worker process
can reconnect.

Disposable acceptance runs the real non-root provider against the root daemon,
using a synthetic TLS runtime service and signed, hash-verified input downloads.
The fixed synthetic Java stand-in runs only inside gVisor. Its deliberately
invalid probe event must produce a workload failure with exact-root terminal
evidence and successful cleanup. All three repetitions and the independent
download, service, kernel and retirement regressions are mandatory. Successful
fixture input copies are removed after their owners close; failed-case evidence
is preserved rather than increasing the container's limits.

This setting is not a production activation instruction. Gateway network-feature
advertisement remains fenced. Measured secrets, real Java/Paper compatibility,
host provisioning, durable storage quotas and end-to-end deployment acceptance
remain outstanding. Production network execution stays disabled.
