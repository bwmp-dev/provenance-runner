# Console-managed hosted binary updates

This first version updates the runner binary on operator-owned platform nodes.
It does not update gVisor, rootfs images, the privileged updater, or customer
self-hosted installations. An administrator selects a release on the runner's
**Manage updates** page. The backend disables new admission, waits for leases and
reserved work to clear, then the root updater checks local terminal replay before
replacing the binary. The gateway must observe a fresh connection reporting the
expected version before admission resumes. Health is operational gateway evidence,
not cryptographic proof of a node's runtime integrity.

## One-time setup

Deploy the platform containing migration 45 and the console's hosted update
routes. Install a hosted runner with the VPS bundle. On your release machine,
create an Ed25519 signing key with `openssl genpkey -algorithm ED25519`. Keep the
private key on the release machine; never place it on a runner or in the console.
Distribute its raw 32-byte public key, base64 encoded, to the node settings and
console updater registration. For an OpenSSL Ed25519 key, the last 32 bytes of
`openssl pkey -in release-key.pem -pubout -outform DER` are those raw bytes.

Create a separate random updater credential on each VPS. For example, as root:

```sh
umask 077
python3 -c 'import secrets; print("pru_" + secrets.token_hex(32), end="")' > /root/updater-credential
```

Create `/root/updater-settings.json`, mode 0600:

```json
{
  "apiOrigin": "https://api.provenance.bwmp.dev",
  "credentialFile": "/root/updater-credential",
  "releasePublicKey": "YOUR_RAW_ED25519_PUBLIC_KEY_IN_BASE64"
}
```

Run the new bundle once with privileged access:

```sh
/root/runner-bundle/install.sh enable-updater /root/updater-settings.json
```

It installs `provenance-runner-updater.service`, a root-only credential and pinned
public key. The command prints only the runner UUID, credential SHA256 and public
key. Enter those in **Manage updates → Register or rotate the node updater**.
The connection credential used by the ordinary runner is separate; neither
credential permits platform administration. The updater requires no inbound port.
Never grant the worker account sudo or access to the updater credential.

A lost/revoked updater credential requires an operator credential replacement;
the console alone cannot install a secret on a disconnected machine. Updating
the updater itself remains an operator task in this version.

## Publish and roll out a binary

Build from the intended source, setting `internal/buildinfo.Version` to the
version recorded in the release manifest. The bundle builder uses `git-` followed
by the first 12 characters of its source commit. Publish the binary at a direct,
immutable HTTPS URL; update downloads deliberately reject redirects.

```sh
python3 scripts/vps/sign-release.py \
  --binary /path/to/runner --version git-0123456789ab \
  --url https://YOUR_ARTIFACT_HOST/runner/0123456789ab \
  --private-key /protected/release-key.pem \
  --output /path/to/release.json
```

Paste the signed JSON into **Publish a signed release manifest**. Select it and
choose **Drain and update**. Start with one node and verify its work before
updating others. There is no automatic fleet rollout in this version. A request
can be cancelled only while it is draining, before the updater claims installation.
The console shows the latest 50 releases and latest 50 requests for a node.

The signature covers a fixed UTF-8 message, including a final newline:

```text
provenance.hosted-runner-release/v1
version:<version>
url:<url>
sha256:<lowercase hex digest>
sizeBytes:<decimal bytes>
```

The binary must be a bounded Linux amd64 ELF. Both the backend and node verify
the signature against the node's configured key; the node independently checks
size and SHA256 after download. An administrator can request an older signed
release explicitly. This is an operator-controlled rollback capability, not an
automatic release ordering or anti-downgrade claim.

## Recovery and limits

The root updater stores its journal and immutable previous binaries in
`/opt/provenance-runner/update-state`, mode 0700. It atomically replaces only
`/opt/provenance-runner/runner`; environment, credentials and job journals stay in
place. It checks the local journal and active user scopes before replacement.
Idle heartbeat replay does not represent unfinished customer work.

On failed health checks the updater restores the previous binary and checks a
fresh gateway connection on the previous version. Successful rollback resumes
admission. Failed rollback or unavailable health leaves the runner drained.
Inspect the node before manual recovery; this version does not offer an admin
force-resume that could bypass drain or broken runtime checks.

A crash after the backend accepts a terminal report must not stop a now-active
runner: the updater persists its terminal-report intent first and retries that
same report. A crash during replacement resolves backend state and restores the
retained binary. It never assumes that lack of local processes proves remote
drain. Host-owned updater files are trusted; customer workloads remain untrusted.

Rootfs/gVisor changes, credential rotation, full signing-key rotation, backup
retention and automatic fleet rollout are separate work. New update deployments
require disposable VPS acceptance, including reboot, an actual Paper job, process
failure, and update/rollback during gateway outages, before production activation.
