# Live authority forwarding

The credentialed gateway supervisor already owns an `AuthorityRoute` for the
active attempt. Successful reconciliations now retain a capability-stripped,
bounded history for a worker-to-root control session. Historical journal data is
not used to construct this feed.

`NextControlUpdate` requires live authority. An initial zero cursor obtains the
latest current update; subsequent calls consume recorded updates in order.
Older acknowledgements cannot replace the latest grant. Returned bytes are
copies, and a blocked reader wakes on renewal, withdrawal, or cancellation.
History is limited to 64 bounded records. An invalid cursor or a consumer that
falls behind withdraws the supervisor rather than skipping deadline reductions.
Forwarding encoding failure stays unavailable; it never creates a replacement
grant or synthesizes newer timestamps.

`measuredclient.ForwardAuthority` is the sole channel writer after `SendStart`.
It checks the job against the live supervisor and requires a kernel-authenticated
root peer. It forwards only recorded reconciliations, with bounded writes and a
total packet limit. Withdrawal or cancellation closes the socket immediately,
including while a send is blocked. Readers may concurrently consume root
observations and results. The caller must cancel and join the forwarder after
consuming completion or abandoning the session.

The disposable full-service client uses this forwarder. Its synthetic Java
stand-in runs longer than the initial two-second authority grant; a fresh update
must reach the root for successful completion. A separate case withdraws after a
real startup observation and requires refusal without a successful result
receipt, followed by controller and journal retirement. Both cases run three
times alongside the existing download and network acceptance suite.

These APIs do not yet wire the production connected worker, provision the root
daemon, enable measured secrets, or establish real Java/Paper compatibility.
Production activation remains guarded and disabled until those integrations and
their acceptance checks are complete.
