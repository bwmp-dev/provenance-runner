# Failed results and authenticated retirement

A refused guest result is never a successful session. If the worker has already
received a root completion receipt when event validation or exit-claim checking
fails, `Run` returns a nil result and a `SessionFailure`. The error still matches
`ErrSession` and exposes neither a successful outcome nor a publishable runtime
observation.

`SessionFailure.RetiredFor(job)` checks the opaque root receipt and the sealed
observation's complete execution binding. A different job, zero value, or JSON
round trip cannot establish cleanup. The receipt is historical: it does not
renew authority or authorize another execution.

The disposable fixture deliberately limits accepted event size below the fixed
synthetic event. Execution finishes and root retires its resources, but event
collection fails. Three repetitions require a failed result, authenticated
retirement for the original job, refusal for a changed configuration, and empty
root-owned journals and bundle directories. Existing withdrawal and pre-release
refusal cases remain mandatory.

This only handles failures after a root completion has actually been received.
Early malformed framing, socket loss, cancellation and signal termination still
return no cleanup proof. Those paths require a separate authenticated retirement
mechanism before production worker capacity may safely be reused. Local socket
closure, a cancelled writer, and guest EOF are not substitutes.
