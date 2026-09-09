# Preparing operator Paper catalogs

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

The current probe support floor is Paper/Minecraft 1.20.6 with Java 21. Newer
versions require matching reviewed Paper, Java and probe compatibility metadata;
preparing an archive alone does not establish plugin or probe compatibility.

Offline boundary tests (synthetic archives and a stub preparation executable):

```
python3 -m unittest discover -s scripts -p test_prepare_paper_catalog.py
```

## Hosted installation and existing nodes

Hosted profiles may supply `paperCatalogs` in place of the legacy `probe` and
`preparedRuntime` fields. Installation verifies and caches all four artifact pins
per catalog, deduplicating shared Java and probe artifacts. The limit is 32 catalogs.
All asset hosts must be in the installation allowlist.

For an existing node, first deploy a runner release supporting
`validate-paper-catalogs`, drain the node in Administration, and wait for its
executions to finish. Stop the worker user service. Place the catalog array in a
root-owned mode0600 file under `/root`, then use the verified new installer bundle:

```sh
sudo bash /root/runner-bundle/install.sh configure-catalogs /root/paper-catalogs.json
sudo bash /root/runner-bundle/install.sh activate
```

Configuration refuses active workers and old binaries, verifies assets before
changing settings, preserves identity and journals, and leaves the worker stopped.
An interrupted update leaves an activation-blocking marker and a private backup
under `/opt/provenance-runner/catalog-backup-*`. Inspect and restore the backup
before clearing the marker. Resume scheduling after reconnecting and testing.
