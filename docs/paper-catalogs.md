# Automatic Paper runtimes

Automatic mode discovers versions in the backend and prepares exact requested
builds on demand. There is no per-Paper-version operator review, offline signing,
fleet catalog installation, or 32-entry global limit. The runtime worker signs
complete manifests automatically with a dedicated key; this is separate from
the offline key used for runner binary releases.

Configure the runner once with `PROVENANCE_PAPER_RUNTIME_ORIGIN` (the HTTPS API
origin) and `PROVENANCE_PAPER_RUNTIME_PUBLIC_KEY_HEX` (32 public-key bytes in hex).
Automatic mode then takes precedence over legacy operator catalogs. Keep the
ordinary customer-artifact host allowlist and resource limits configured. The
runner reads the signed manifest matching the job's exact Paper digest/build and
Java version, verifies its signature and source authority, and lazily caches
only its four artifacts. The signed manifest is retained in local job state so
recovery verifies the same bytes. Different jobs do not mutate a shared catalog.

The platform worker setup is documented in `docs/automatic-paper-runtimes.md`
in `provenance-platform`. Its preparation image is built from this repository:

```sh
docker build -f scripts/paper-preparation.Dockerfile -t provenance-paper-preparation .
```

Deploy that image by digest on the dedicated preparation host. The worker runs
it under gVisor with quotas and a dedicated network, and supplies only a temporary
directory of public runtime inputs. Neither the signing key nor backend
credentials enter this container. New Paper builds need no image rebuild.

Probe 0.2.0 supports the Java 8/legacy Bukkit baseline. The same immutable JAR
passed offline gVisor lifecycle and command tests on Paper 1.8.8/Java 8 and
Paper 1.21.8/Java 21. This is representative acceptance, not an exhaustive test
of all upstream builds. Exact Java 8/11/16/17/21/25 templates are shared across
compatible builds. Original probe 0.1.0 pins remain valid only for modern Paper
1.20.6+ catalogs, allowing rollback without relabeling old bytes.

## Legacy manual preparation

The commands below remain available for bootstrap, diagnostics and compatibility
with runners that have not enabled automatic mode.

The operator preparation tool consumes a complete reviewed catalog and local
checksum-pinned Paper JAR and Java archive. It performs no downloads. Choose
Paper artifacts from official Paper distribution metadata and Java archives from
the selected Java distributor; put their exact SHA-256, sizes and identities in
the catalog. A path to an arbitrary installed Java executable is insufficient.

Build the trusted preparation command from accepted source:

```
go build -o /tmp/provenance-paper-runtime ./cmd/provenance-paper-runtime
python3 scripts/prepare-paper-catalog.py \
  --catalog /private/catalog.json \
  --java-archive /private/java.tar.gz \
  --paper /private/paper.jar \
  --runtime-tool /tmp/provenance-paper-runtime \
  --runtime-uri https://assets.example.invalid/paper-runtime.tar.gz \
  --maximum-prepared-bytes 1073741824 \
  --output-dir /private/prepared-new
```

The output directory must not exist. It receives `paper-runtime.tar.gz` and a
complete `catalog.json` with the resulting prepared archive pin, both mode 0600.
Upload that exact archive to the operator-selected asset URI, then install the
catalog through the runner's trusted configuration. URLs stay in the private
catalog; command output does not print them or subprocess output.

The tool verifies both input hashes and sizes before execution, extracts Java
into a private temporary directory with expanded-size and entry bounds, rejects
special files/path traversal and unsafe symlink chains, and runs only the trusted
Paperclip preparation command with pinned Java. Customer plugin JARs must never
be supplied as `--paper`. This is operator preparation, not a hosted plugin test;
actual plugin execution belongs inside the runner's gVisor sandbox.

Legacy Paperclip output uses `cache/mojang_<version>.jar` and
`cache/patched_<version>.jar`; modern output uses the existing cache, libraries
and versions roots. Both paths retain exact-version checks, deterministic
archives and symlink/size/entry rejection. The runner uses the cross-generation
`nogui` argument. Preparing an archive alone does not establish plugin
compatibility; target plugin Java/API requirements still apply.

Offline boundary tests (synthetic archives and a stub preparation executable):

```
python3 -m unittest discover -s scripts -p test_prepare_paper_catalog.py
```

## Hosted installation and automatic reconciliation

Hosted profiles may supply `paperCatalogs` in place of the legacy `probe` and
`preparedRuntime` fields. Installation verifies and caches all four artifact pins
per catalog, deduplicating shared Java and probe artifacts. The limit is 32 catalogs.
All asset hosts must be in the installation allowlist.

Existing and newly installed nodes use the privileged updater's signed desired
state. Upload each exact catalog asset with `provenance-hosted-assets --kind
catalog --name <filename> --file <path>`; the backend stores it by SHA-256. On the
offline release machine, turn the reviewed catalog array into a signed revision:

```sh
python3 scripts/vps/sign-catalog.py \
  --catalogs /private/paper-catalogs.json \
  --api-origin https://api.provenance.bwmp.dev \
  --private-key /protected/release-key.pem \
  --output /private/signed-paper-catalog.json
```

Publish that revision through `POST /v1/admin/hosted-catalogs` (or the
`provenance-admin hosted-catalog` operator command), then assign its digest to a
sorted list of up to 200 hosted runner IDs in one audited, idempotent request.
This is the global rollout primitive: use a one-node list as the canary and a
larger list after verification. The backend drains every target transactionally;
each updater then verifies the signature, validates the complete catalog with the
installed runner, fetches only credential-scoped content-addressed assets, fills
the worker cache, atomically activates the environment, and waits for a fresh
gateway capability report before admission resumes.

Failures before activation leave the node drained. Failed post-activation health
restores the root-private settings/environment backup and proves another fresh
connection before reporting rollback. The updater journal makes activation and
terminal reporting crash-safe. The backend records desired, previous and active
catalog digests per node; reassigning the active digest is refused rather than
silently rewriting history.

Paper discovery can propose a new version, but it cannot directly mutate fleet
state. A new environment still requires reviewed Paper/Java/probe compatibility,
a prepared immutable runtime, uploaded hashes, an offline signature, and explicit
administrator assignment. Jobs never resolve a mutable `latest` version or fetch
unapproved upstream bytes.

The older `install.sh configure-catalogs` command remains only as a bootstrap and
disaster-recovery tool for a stopped node. It is not the normal fleet update path.
