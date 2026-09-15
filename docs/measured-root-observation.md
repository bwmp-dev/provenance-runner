# Runtime observation across the root boundary

The credentialed worker cannot inspect the root controller's protected kernel
objects itself. A dedicated local `Observation` packet transfers a historical
observation from that privileged owner, separate from ordinary `Result` packets
used for guest output. The root service must send this fixed phase before relaying
guest output and must never let the guest choose the packet kind.

The producer exports only an already sealed observation whose SHA-256 binding
matches the entire execution specification, excluding only ephemeral download and
log-upload URLs and their expiry timestamps. Object keys, sizes, filenames,
digests, secret references and all other execution fields remain bound. Kernel
observation freezes that binding in addition to the existing lease/attempt/hash
binding. Root and worker therefore agree even after transfer capabilities refresh.
The payload contains a fixed version, the job digest and a bounded canonical
snapshot. It has no credential or continuing authority.

Only receiving the dedicated kind from a kernel-authenticated UID-0 peer can
construct the opaque receipt. Wrong peers, ordinary result packets, unexpected
descriptors and invalid framing close the channel. JSON cannot recreate the
receipt, and exposed payload bytes are copies. Import requires that receipt,
the exact full job digest, the job's enabled network mode and a complete canonical
runtime identity. Forged receipts, changed jobs and malformed snapshots fail.

Import delegates historical measurement to the authenticated privileged owner;
it does not pretend that the worker re-observed the kernel objects. The resulting
execution-bound observation may enter `BuildObservedNetwork` only when its full
execution digest also matches the terminal-evidence context. Reusing the same
lease and hashes with a changed target cannot produce evidence. Its value-only
snapshot still fails the legacy `Snapshot.Valid` path for enabled networking.
Neither import nor historical journal validation authorizes a new route, renews
an expired acknowledgement or proves a successful test or completed cleanup.

Disposable acceptance transfers a real live sandbox observation to a non-root
client over the protected listener. The client checks exact binding, rejects a
changed full job and a JSON-recreated receipt, and verifies copied payloads cannot
mutate retained proof. Dedicated malformed and wrong-kind cases must refuse.
The enclosing case still withdraws the router and proves complete owned cleanup.

Daemon dispatch, worker execution integration, sealed test-secret injection and
production activation remain separate gates. This adds no public launch API and
does not widen the existing production network-v2 fence.
