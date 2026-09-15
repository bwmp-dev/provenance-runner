# Execution-bound observed network runtime evidence

Network runtime claims use a separate sealed path. `Lease.ObserveNetwork`
requires the exact retained workload's resource proof, current native route
authority, and actual live executable/read-only SquashFS root measurement. It
checks resource enforcement and route authority again after object measurement.
The result retains immutable lease, attempt and hash bindings, never credentials
or URLs. Its private fields cannot be populated by decoding JSON.

`MeasuredNetworkProcess.ObserveRuntime` exposes this observation only while its
released owner remains alive with valid journaled ownership. Refusal withdraws
authority and triggers scope cleanup. A historical observation cannot revive
authority, grant another attempt access, or establish guest success.

`terminalevidence.BuildObservedNetwork` accepts this sealed object only for the
original validated v2 context and original network mode. It preserves ordinary
assertion/completeness rules. The original `Build`/`Snapshot.Valid` path continues
to reject unsealed restricted/allowlist labels, including snapshots copied out
of an observation. There is no JSON-to-observation constructor.

Frozen v2 journal validation recognizes the same closed runtime representation,
reconstructs its canonical bytes and checks exact equality against the saved
digest/binding. This is historical validation, not a new measurement or authority
grant; journal authenticity remains the existing owned journal/delivery boundary's
responsibility. The v1 reader remains unchanged in accepted network modes.

Disposable tests combine the real sandbox observation with synthetic validated
job metadata and produce partial terminal evidence with no Paper/plugin success
assertions. They reject another attempt and the unsealed projection; withdrawal
refuses fresh observations while preserving the earlier evidence bytes. The
existing v2 reference validator independently checks the valid representation.
Producer tests also refuse unsupported modes, mismatched mode, malformed hashes
and extra fields.

Production provider selection, root RPC, native route provisioning/recovery,
secret/event channels and hosted acceptance remain separate requirements. This
change does not enable network V2 or declare alpha acceptance complete.
