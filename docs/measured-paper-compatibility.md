# Real Paper measured-session acceptance

The real-workload fixture exercises Paper 1.21.8 build 60, Temurin JRE
21.0.8+9, the published alpha probe and the `ProvenanceSuccess` fixture plugin
through the non-root worker and root daemon. Java executes only inside the
measured gVisor guest, never directly on the fixture host.

The controlled command is `version ProvenanceSuccess`, with the exact expected
response `ProvenanceSuccess version 1.0.0`. Bare `version` is unsuitable for this
offline positive test: Paper starts an asynchronous internet update check, which
the fixture's unchanged network restrictions deny. Assertion failures remain
workload failures; the validator is not relaxed to ignore them.

This acceptance exposed a provider integration defect. The framed collector's
provider-neutral `probe` channel must be projected into Paper's
`paper_probe_event` channel before applying the existing complete lifecycle
validator. Only that known channel label is mapped. Payloads, ordering,
requirements, command assertions and shutdown validation remain untrusted and
unchanged. Unit tests cover a valid transcript, invalid payloads and unrelated
channels; none of these events can manufacture a runtime observation.

## Reproducible fixture inputs

`scripts/network-policy/build-paper-compatibility-root.py` builds only inside a
fresh disposable container. It verifies the accepted Ubuntu 24.04 OCI export,
the complete prepared-tree hash, normalized source archive, pinned builder and
exact static helper, then requires two identical SquashFS builds. The guest
mount targets use UID/GID 65532. It installs or activates nothing on the host.

- Normalized source: `c9a44780f9e5ae2d33be83a1a5b69c8fc95fddc99d86d327b74f6adaaab08095`
- Helper: `69991043ce8c4c640163d70e484b4b1af009f3e82bc6e847d97815a464b81275`
- Root image: `94862cd9a2d88c29421e281166cf59a7190336eb1c0365cdb7fca55e89f8f361`

`stage-paper-compatibility-assets.py` verifies the pinned official Java and Paper
archives plus the known fixture plugin. It creates a deterministic, bounded
prepared archive from only `cache`, `libraries` and `versions`. No plugins,
credentials, world state or server configuration are copied into that archive.
Staging never runs Java or interprets a JAR.

## Running the acceptance

On the explicitly prepared Linux integration host, supply the verified fixture
image, previously built root image and staged input directory:

```sh
python3 -B scripts/network-policy/paper_acceptance.py \
  --image sha256:<verified-fixture-image> \
  --rootfs /absolute/path/rootfs.squashfs \
  --inputs /absolute/path/inputs
```

The driver creates a fresh read-only, network-none container with private cgroups
and explicit outer limits (6 GiB memory, four CPUs and 1024 processes). Each
actual workload receives two CPUs, 2 GiB memory, 2 GiB disk and 256 processes,
with 90-second preparation and 180-second execution budgets. These are separate
real-Java fixture allocations, not increases to the smaller synthetic suite.

All three repetitions must pass root provisioning checks, authenticated startup,
Paper lifecycle/command validation, exact-root terminal evidence and a subsequent
idle barrier. The driver checks journal and cgroup retirement, exact owned loop
detachment and container exit status, including OOM status. Failure evidence is
retained. It never adopts or detaches an unrelated host loop device.

The complete synthetic service/kernel suite remains separately mandatory. This
test is not a claim that all Paper versions, measured secrets, production host
provisioning, protocol activation or deployment acceptance are complete.
