# Bounded late secret descriptor transport

The local authenticated control channel has a dedicated secret-delivery kind.
One canonical metadata packet carries only ordered names and expiry, followed by
exact batches of up to 16 read-only file descriptors, at most 64 in total. Values
never enter packet payloads. All packets share a deadline of at most five seconds;
neither interleaved authority packets nor repeated headers extend it.

The receiver requires the exact expected names and a current lease expiry ceiling,
rejects noncanonical or unknown metadata, and closes every received descriptor
and the connection on malformed or incomplete assembly. The sender borrows its
files. Successful receipt transfers descriptor ownership to the receiver, which
must retain and close them explicitly. Received objects suppress ordinary JSON
and formatted diagnostics.

Tests exercise real local descriptor transfers at batch boundaries, sealed file
reading, subsequent control-message sequencing, metadata substitution, expiry,
partial FD cleanup and the shared timeout. These are transport tests, not proof
of authenticated end-to-end secret delivery. The service must enforce the phase,
single delivery, selected immutable references, job/lease/attempt binding and
sealed-memory profile before materialization; the worker must authenticate root,
hold its control-writer lock, and register redaction before Java release.

No scheduling feature is enabled by this protocol primitive.
