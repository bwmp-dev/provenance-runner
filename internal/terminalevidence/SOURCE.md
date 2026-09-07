# IFC-019 producer inputs

The configuration schema and offline terminal-evidence reference, schema and
vectors are exact copies from `bwmp-dev/provenance` contracts v0.1.0-alpha.16,
source `f17e6b0db9507cbf1325769bc23c1d288101f89a`, annotated tag
`255565aa4d836301c3d6b7d742d8fbe4d8b801df`. Apache-2.0 license is retained in
`schema/LICENSE`. The JSON parser/canonicalizer is adapted from that source's
`packages/verification-go/json.go`; it is not a separate public API.

SHA-256 identities:

- config schema: `11015605ee709d3ea032c064065b411227d500b0c94cbdf640627189d3016778`
- terminal schema: `838d75a63cfbecc0697c4fad38c484a8f4790c802f9f1d919a764edd1991657e`
- offline reference: `27da7c97fcb8aeab356a6edf101bdceceefb2f0170423cc21f1c2e0c09168326`
- fixtures: `db0555744db814e135e0374546fbf49211c40ae657ba357fa378dc3151a082aa`
- vectors: `186a4002b72bdae74129ef2248e030f7c95da72a935b2825790bb3d915e05923`
- invalid vectors: `1453a5aa67a5fc9387afff9d2c0c05c142ffd9cb0f1bbbd004cdff4b29a9b823`

`platform-created-job.json` was emitted by an isolated PostgreSQL 18/schema33
diagnostic at platform `eb6a0f572d497780cc4257d6b2d03927a09488b3`, using the existing release integration fixture
and actual `PostgresActivityHandler.CreateJob` persistence path. The temporary
test was `TestLocalProducerParityDiagnostic` in the parent-owned diagnostic
worktree. It rejects every populated URI/URL/upload/secret/token/credential
field before emission. The fixture is synthetic, not a hosted execution; no
provider or production database was contacted. Exact file SHA-256 is
`6f6dcb25753a2dd4b4a54f7f4e4dfe1445de6126f5464c2a3cddf159addc0e8d`;
without its final newline it is
`435329914a5cb6b7af1ab60b341c88bb5dc8419cf2978a1bd19bf74ec550cc0a`.
Tests add only synthetic lease/attempt binding to the persisted template.

Production emits **partial** evidence with `runtime: null`. This package does
not measure the mutable rootfs, attest the runtime, sign statements, or claim
FIFO events are independently authenticated against a malicious co-tenant
plugin. Only explicit regex assertions are projected; contains/default
operators and absent observations cannot become verified outcomes. Context is
frozen before execution; proof bytes are frozen before durable terminal enqueue.
An unadvertised reconnect cannot strip or send queued proof. Legacy queued
terminal messages with no evidence remain valid.
