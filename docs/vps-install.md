# Platform-hosted runner VPS installation

This installer is exclusively for operator-owned runners in the Provenance platform
pool. Customer self-hosted runners will have a separate installation workflow.
Organization enrollment fields are rejected.

Use `scripts/vps/build-bundle.sh` on a trusted build machine, then run the bundled
`install.sh` as root on a **fresh Ubuntu 24.04 LTS amd64 VPS with systemd, cgroup
v2 and AppArmor**. The VPS needs outbound HTTPS and enough CPU, memory and disk
for the capacity you advertise. No inbound runner port is required.

This is a first-install path for the existing gVisor runtime. It does not replace
the measured-generation upgrade tools or claim measured-runtime attestation.
It refuses existing paths/accounts instead of overwriting credentials, jobs or
journals. A dedicated locked `provenance-worker` account runs jobs, distinct from
your SSH account. The VPS does not need Go, Docker, GitHub credentials or access
to platform data services.

## Build once, reuse the bundle

On your trusted Linux build machine, with Go, Docker, curl and Python 3 installed:

```sh
cd provenance-runner
scripts/vps/build-bundle.sh /absolute/path/runner-bundle
scp -r /absolute/path/runner-bundle your-vps:/root/
```

Use a committed checkout. The builder compiles the runner for Linux amd64,
downloads the checksum-pinned gVisor release, and exports the digest-pinned Ubuntu
image without starting it. It records source commit and SHA256 checksums. It
removes only its own temporary Docker container. The same bundle can provision
multiple VPSes; each VPS needs its own runner registration and settings.

The bundle is trusted executable installation code: transfer it through your
trusted SSH connection and keep it under `/root`, owned by root, without writable
ancestors. Its checksum inventory detects accidental damage; it is not a signature
or independent proof of origin. Do not use an untrusted bundle/checksum pair.

## Configure each VPS

Register a platform-pool runner through the platform operator workflow and obtain
its runner connection credential. Save it to a root-only file on the VPS, not in
a command argument, shell history or this repository. This installer consumes an
already-issued credential; it does not create platform registrations.

Copy `settings.example.json` to `/root/runner-settings.json`, then fill in:

- The deployed gateway DNS name, TLS port, and registered platform runner UUID.
  The gateway must support trusted native TLS with HTTP/2.
- `platformCredentialFile`: the absolute path to the root-only runner connection
  credential. Never supply API management, database, Temporal or storage credentials.
- `artifactHosts`: exact DNS hosts used by jobs and pinned runtime assets, including
  any Java/Paper/dependency hosts the platform's jobs require.
- Published HTTPS URIs for the accepted probe and prepared Paper runtime, with the
  actual prepared archive SHA256, byte size and expansion bound. The probe pin is
  already populated. The installer verifies both downloads before provisioning.
- Capacity to advertise. Leave headroom for the host; capacity must not exceed the
  host's CPU/memory or available disk. Per-job CPU, memory, process, timeout and
  output limits remain enforced by the runner.

This installer configures the supported single-runtime composition:
**Paper 1.21.8 build 60 / Temurin 21.0.8+9**. Prepare/publish its archive using
`cmd/provenance-paper-runtime` on a trusted build machine. It does not build or
publish platform artifacts on the execution VPS. Full three-environment catalog
provisioning remains separate from this first-install helper.

```sh
chmod 600 /root/runner-settings.json /root/platform-runner-credential
/root/runner-bundle/install.sh install /root/runner-settings.json
```

The command installs host packages, verifies published assets, creates the account,
installs gVisor and its path-specific AppArmor user-namespace permission, prepares
and verifies the pinned root filesystem, installs boot services and starts the platform runner. It does not disable AppArmor, change global sysctls, modify SSH,
open inbound ports, grant sudo or add the worker to the Docker group.

The backend must already provide the gateway, platform runner registration and
artifact hosting. Credential issuance, rotation and revocation remain part of
platform operations; no organization enrollment or one-time registration token is
used by this installer.

## Prepare now, activate later

```sh
/root/runner-bundle/install.sh install /root/runner-settings.json --prepare-only
/root/runner-bundle/install.sh activate
```

Preparation still requires valid settings, published assets and a platform runner
credential file, but it does not contact the gateway or start the runner.
Activation verifies gateway TLS/HTTP2 before starting the worker. If activation
fails after installation completes, fix the gateway or credential prerequisite
and rerun `activate`; it preserves the installed credential and journal.

If preparation itself fails after provisioning starts, `/opt/provenance-runner/INSTALLING`
marks the incomplete installation. Inspect the retained state or rebuild the fresh
VPS; rerunning installation will not adopt or erase it. No automatic destructive
rollback or upgrade is provided.

## Operation and verification

```sh
systemctl status provenance-runner
systemctl stop provenance-runner
systemctl start provenance-runner
```

The system service controls a user service. A system service showing `active
(exited)` means the lifecycle wrapper completed, not that the worker is connected.
Inspect the actual worker with:

```sh
worker_uid=$(id -u provenance-worker)
runuser -u provenance-worker -- env XDG_RUNTIME_DIR=/run/user/$worker_uid \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$worker_uid/bus \
  systemctl --user status provenance-runner
journalctl _UID="$worker_uid" --since '10 minutes ago'
```

Keep journals private. The worker restarts on failure and keeps its durable
connection journal beside its credentials. At boot the system wrapper verifies
and restores the read-only rootfs before starting the user service. Do not enable
the user service separately, as that would bypass boot ordering. Job scopes live
in the user's `app.slice`, where the existing runner enforces cgroup quotas and
reconciles stale work after restarts.

Confirm the runner is online in the console, submit a known-safe Paper smoke job,
and confirm its outcome and complete logs. The installer's short process check
only proves startup, not credential longevity, gateway heartbeat acceptance or a
successful sandboxed job. Record the installation identity from
`/opt/provenance-runner/installed.json` and verify reboot behavior before admitting
customer work. This new installer needs a disposable fresh-VPS acceptance run;
unit tests and rootfs fixture checks are not live deployment evidence.

## Development checks

```sh
python3 -m unittest discover -s scripts/vps -v
bash -n scripts/vps/install.sh scripts/vps/build-bundle.sh
```
