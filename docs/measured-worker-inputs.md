# Worker input preparation

`paper.Provider.PrepareMeasuredInputs` is a worker-side preparation API. It is
not a launch method and does not enable network-v2 job execution in the gateway.

The worker fetches the public signed runtime manifest under the caller's
cancellation context and preparation timeout. It validates the same closed
request and derived input plan used by the root service before downloading any
artifacts. Test-secret jobs remain refused until measured secret delivery exists.

Runtime downloads use exact signed source URLs and the existing pinned-source
policy. Target and dependency downloads use the configured HTTPS host policy,
public-address validation, and redirect checks. Existing cache entry, total,
per-artifact, dependency, and preparation limits remain applicable. No archive is
extracted and no JAR is executed by this API.

Every cache acquisition requires the exact byte count and SHA-256. Every returned
descriptor is read-only and is rechecked with a bounded read before handoff. The
returned owner contains only the projected request and descriptors; artifact
download URLs do not enter the root request. The root still independently copies
and verifies inputs because a worker-owned cache is not immutable or trusted.

Callers keep the owner alive through `SendStart`, then close it. Failed partial
preparation closes all descriptors already acquired; valid downloaded entries
remain in the quota-bounded cache for reuse. Per-source idle HTTP connections are
closed when preparation returns. The owner is single-consumer, not concurrency
safe; its descriptor slice contains borrowed descriptors.

The disposable download fixture runs as UID/GID 65532 with no external network,
a read-only root, and bounded memory, processes, and temporary storage. A local
TLS fixture serves a synthetic signed catalog, synthetic input bytes, and the
published hash-pinned probe as data. It verifies the complete preparation path
twice per run, including cache reuse and independently derived root identities.
Three runs are mandatory in measured acceptance. This is not Java/Paper execution
or complete worker-to-root session acceptance.

The remaining bridge must send fresh authority reconciliations, receive the
authenticated observation and retired result, redact and validate guest output,
and construct correctly bound terminal evidence. Root daemon provisioning and
guarded production activation remain separate requirements.
