# Root Paper request dispatcher

`internal/measuredservice` composes the local authenticated control channel with
the measured controller. It is a library, not a deployed daemon or an enabled
gateway execution path.

Root provisioning supplies the controller, retained measurement, catalog public
key and origin, worker UID, and input limit. Requests cannot select root commands,
tool paths, credentials, or network policy beyond the provisioned boundary. The
root service does not download URLs or load platform credentials.

Admission is serialized before reading request bytes or receiving descriptors.
The service verifies the signed catalog and derives the input roles, receives a
fresh authority reconciliation, and launches the fixed measured Paper helper.
The helper's startup marker precedes the live runtime observation; configuration
is delivered only after that observation succeeds. Empty preparation messages
keep the bounded request session alive without granting execution authority.

Guest output remains untrusted. The service forwards bounded result bytes and
sends a separate root completion only after the controller proves process and
resource retirement. The worker must still validate framing, redact logs,
validate Paper events, compare the actual exit outcome, and bind terminal
evidence to the same execution. EOF alone is not successful completion.

Failed cleanup retains ownership and prevents admission. Authority loss,
disconnects, cancellation, and output limits do not permit resumption. Test
secret requests remain explicitly refused pending measured secret delivery.

The disposable kernel fixture uses a published hash-pinned probe as input data
and a trusted Go executable as a synthetic Java stand-in. It does not execute
the JARs or establish real Java/Paper compatibility. The acceptance driver
requires three successful full-service runs in addition to the existing network
and cleanup checks. Ordinary unit tests skip the privileged kernel fixture.

Remaining integration includes root daemon provisioning, the credentialed worker
bridge, measured secret delivery, real Paper acceptance, and guarded production
activation. Production must not advertise this path based on library tests alone.
