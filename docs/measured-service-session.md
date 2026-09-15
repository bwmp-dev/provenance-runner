# Measured service startup and result phases

The measured Paper helper emits the exact eight-byte `PVREADY1` marker before
reading bootstrap configuration. The root owner consumes that marker under the
job deadline, performs the existing fail-closed kernel observation, and only
then supplies configuration and closes bootstrap input. The marker is merely
synchronization: it cannot replace measurement or permit an observation retry
after authority withdrawal. This avoids racing measurement against a fast guest
exit and ensures that bootstrap cannot begin guest preparation beforehand.

After the separate authenticated `Observation` phase, worker result transport
uses only `Result` packets for the untrusted framed guest stream. Aggregate
transport is bounded to 21 MiB and 32,768 packets, including empty keepalives.
The root must send a keepalive at least every 20 seconds during quiet execution;
reads have a 25-second socket deadline bounded by the job context. Cancellation
closes the owned channel, including when a read is blocked.

Only a separate root-authenticated `Completion` packet ends the stream normally.
It contains a fixed version, actual process exit code and infrastructure-failure
flag. The root producer must use `CompletedProcessOutcome` after successful
resource retirement. Only the exact owned command's ordinary `ExitError` is a
process outcome rather than an infrastructure failure; joined or substituted
errors remain failures. Paper helper exit 125 and invalid guest output must still
be classified as infrastructure failure by the provider. A zero exit alone
does not establish success. Connection loss, unexpected descriptors, invalid
phases and malformed completion discard the receipt and fail closed. Receipt
fields are private, so JSON cannot reconstruct authenticated completion.

The worker must still validate the guest stream, redact logs, validate Paper
lifecycle events, compare guest claims with the root result and bind observed
runtime evidence to the exact job. Neither framing nor completion proves plugin
compatibility. Unit parser fixtures use same-user sockets and do not claim root
authentication or actual kernel completion.

Disposable Paper acceptance additionally captures the helper's live observation
before bootstrap, waits for actual kernel exit and full retirement, then transfers
the historical observation, bounded guest stream and completion to a non-root
client. Both the successful synthetic preparation and reserved helper-failure
cases must pass three times. These are synthetic preparation tests, not evidence
of compatibility with a real Paper/JRE distribution or customer plugin.

This is not a deployed root daemon. Full request dispatch, completion production,
worker integration, measured secret injection and guarded production activation
remain separate acceptance gates. Existing production networking stays disabled.
