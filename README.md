# Provenance Runner

Public Go runner for hosted and self-hosted Provenance execution.

The same binary connects outbound to the runner gateway and executes resolved jobs under the locally permitted sandbox and network policy. Hosted deployment uses gVisor; a development driver supports protocol and provider work where gVisor is unavailable.

The current alpha slice accepts a bounded local job document and emits a structured result:

```sh
go run ./cmd/provenance-runner execute job.json
```

The local CLI currently registers only `development-process`. It requires
`"acknowledgeUnsandboxed": true` in its environment configuration because it runs a command
directly on the host. It is for runner-core development and is not a security boundary.

The runner core also includes a Linux gVisor provider for hosted integration. It builds a
locked-down OCI bundle and invokes `runsc` directly, without a Docker daemon or socket. The
provider is configured by the trusted host integration rather than the local CLI so job input
cannot select the root filesystem, state directory, or host mount roots.
