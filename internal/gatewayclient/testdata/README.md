# Paper workload-failure regression chain

`paper-workload-result.json` is a test-only classification projection, not a new
public result schema. `TestExecutorPreservesValidatedProbeFailureCode` in
`internal/provider/paper/provider_test.go` checks its status, classification,
executor phase, failure code/message and internal stage against actual Paper
provider and executor output using an isolated fake sandbox (no customer code).
The internal stage is deliberately excluded from public local-runner JSON.

`TestPaperWorkloadFailureWireFixtureAndReplay` consumes that checked projection
through the actual gateway serializer and compares `paper-workload-failed.json`
as a protobuf `JobFailed`. Only fixture lease/attempt IDs, timestamps, measured
usage and uploaded log identity are fixed. No failure classification is rewritten.
The test also checks disconnect replay and conflicting/valid acknowledgements.

This wire fixture uses the existing released protocol. It is not hosted runtime
evidence. `JobFailed` has no started-at/process-exit fields: start acknowledgement
and standalone usage remain separate protocol events, and terminal failure keeps
its measured usage, uploaded complete log, failed-at and lease/attempt identity.
The existing start-acknowledgement-before-execution tests remain mandatory.

Consumers may substitute their run-local lease/attempt/time and log-upload binding,
but must document those substitutions and preserve failure and usage fields.
