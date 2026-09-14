# Current authority execution ownership

`execution.SuperviseNetworkAuthority` refuses worker invocation without a fresh
guard for the exact original policy, job, lease and attempt. A trusted context
handoff makes that same guard available to the sandbox; it is not an environment
JSON field, a namespace selector, or proof that a route has been installed.

The guard independently cancels execution on withdrawal or expiry. The supervisor
waits for the normal worker result and cleanup before returning. Network loss is
an infrastructure failure, not plugin incompatibility or candidate cancellation.
An existing cleanup failure remains a cleanup failure. A failed route teardown
adds an explicit failed cleanup result, feeding the existing runner drain/no-slot-
reuse path. `Done` alone never releases capacity. Successful teardown initiated
after normal worker completion does not turn a successful run into a failure.

The gateway worker entry point wraps enabled v2 network jobs with this owner;
without the in-memory guard it produces an early preparation failure without
calling the provider. It neither reconstructs authority from the journal nor
claims execution/cleanup occurred for this early refusal. Legacy and network-none
workers retain their existing execution path.

Local tests cover missing/changed/withdrawn guards, independent expiry, context
handoff, waiting for worker cleanup, successful completion, cleanup-error priority,
and the actual gateway worker-event path. Authority loss produces an ordinary
durable failed event; the active lease remains until acknowledgement, and no
cancellation identity is invented. Full runner race tests and vet pass.

This is the worker ownership boundary, not feature activation. The next stream
integration must feed only authenticated, identity-matched acknowledgements into
the guard, handle pre-worker withdrawal and reconnect/restart without revival,
and preserve terminal cleanup bookkeeping. Production offer/Paper admission and
network capability advertisement remain fenced. Provider namespace ownership,
measured runtime proof, hosted acceptance and rollout remain separate gates.
