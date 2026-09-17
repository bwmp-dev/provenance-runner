# Hosted measured service launcher

The root-only `measured-service-launch.py` entrypoint binds the existing measured
daemon to verified hosted storage, image selection, identities and systemd
delegation. It accepts only launch (no arguments) or the fixed `prepare-boot`
phase, with no path overrides, and reads only the protected root:root `0600`
plan `/etc/provenance/measured-launch.json`. It never formats,
drains, changes forwarding, loads gateway/marketplace credentials, starts
the worker or installs units. Provisioning and activation remain separate.

The version-1 plan contains `{path,sha256}` pins for `runner`, `config`,
`bootPlan`, `storagePlan`, `unit`, `secretMount`, `launcher`, `bootHelper`,
`generationHelper`, `storageHelper` and `inventoryHelper`. Executable/helper paths
are fixed beneath `/opt/provenance-runner`; daemon configuration is fixed at
`/etc/provenance/measured-service.json`. Unit bytes and loaded fragments must match
the generated templates, without drop-ins or pending reload. The installing
coordinator pins the plan and helpers; root custody is the runtime trust boundary.

The daemon configuration must select the same measured root, runsc and runner as
the boot/launch plans. Persistent state is fixed beneath
`/var/lib/provenance-measured/data`, backed by the verified 8 GiB filesystem.
`bundles` is root:root `0711`; `cgroups`, `bundle-journal` and `uplinks` are
root:root `0700`. The socket directory is `/run/provenance-measured/socket`.
Secrets use their separate root:root `0711`, noexec/nosuid/nodev/noswap tmpfs at
`/run/provenance-measured/secrets`, limited to 1 MiB and 256 inodes. Nested mounts,
filesystem capacity drift, wrong backing objects and mismatched selection refuse.

This initial hosted profile uses worker UID994/GID981 and four reserved numeric
UID/GIDs: 262144/262145 for workload/root-overflow and 262146/262147 for the router.
The corresponding `provenance-job`, `provenance-job-overflow`,
`provenance-router` and `provenance-router-overflow` accounts must remain
non-login, password-locked, without supplementary membership. Borrowed primary
groups, duplicate identities and subordinate-ID overlap refuse. Process/file
ownership inventory and initial reservation are separate operator requirements;
startup does not reinterpret surviving job processes as fresh reservations.

## Resources and lifecycle

The generated service uses `DelegateSubgroup=controller`; its main process must
actually reside there, alone, with an empty service parent. It enables cpu,
memory and pids only within that delegated parent, never in an ancestor. The
root unit envelope is 600% CPU, 12 GiB RAM, no swap and 2048 tasks. The controller
subgroup is separately bounded to one CPU, 512 MiB and 256 tasks.

The sibling `jobs` aggregate must match the existing Go `ControllerResources`
contract exactly: twice the maximum job CPU/RAM, twice `(processCount + 17)`
tasks, no swap or CPU burst, two immediate descendants, depth one and grouped
OOM handling. These are not approximate ceilings. The hosted profile bounds
each maximum job to 2000 CPU milliseconds, 4 GiB RAM, 8 GiB disk and 512 processes;
maximum staged input is 1 GiB. The daemon independently validates the full
policy. Existing child groups may be recovered only with unchanged aggregate
controls; the launcher refuses to rewrite an occupied parent's drifted limits.
Actual capacity must still be verified against host and ancestor limits before
advertising it; systemd maxima do not reserve physical resources.

After verification, the launcher clears the environment and supplementary groups
and executes the retained, hash-checked runner FD in `measured-service` mode.
Only the fixed root systemd notification socket is retained in the environment.
The daemon sends `READY=1` after protected provisioning/recovery and listener
creation, not merely after process creation. A notification failure closes the
daemon through its ordinary ownership-retaining cleanup. Direct operator/fixture
invocation without `NOTIFY_SOCKET` remains supported; alternate notification
paths are refused. Guest/router children retain their existing closed environments.

The service uses `Type=notify`, so a dependent worker wrapper can wait for actual
readiness. Stop signals the main owner and waits without a forced cleanup timeout
or final SIGKILL. Cleanup failure therefore retains ownership and prevents a
successful stop claim. Restart-on-failure reopens the persistent journals; their
existing recovery rules remain authoritative. Socket runtime directories are
preserved across service restarts. Mount dependencies stop in reverse order after
the daemon; neither the launcher nor daemon force-detaches operator storage.

Its native `ExecStartPre` runs `prepare-boot` after the three required mounts and
the explicitly required/ordered `user@994.service` manager are active, and before
daemon measurement. The same pinned plan, units, helpers and
identity checks apply. This phase requires systemd's actual `activating/start-pre`
state, verifies persistent/secret storage and invokes the existing stopped-worker
image preparation boundary to repair only the private loop-device alias. It never
changes a global loop mapping. A worker's later pre-start hook cannot do this:
native worker `Requires`/`After` waits for the root controller first, including
during signed updates. The root unit therefore owns this boot readiness step;
removing the worker's dependency or relying on warm loop-number reuse is invalid.

## Acceptance

The standard networkless systemd fixture exercises actual delegated placement,
separate controller/job budgets, a real job leaf, occupied-parent and outer
envelope drift refusal, bounded noswap secret tmpfs, notification readiness and
owned group/mount cleanup. Its child command is synthetic and does not claim a
complete daemon launch. The initial fixture refusal showed that delegation makes
controllers available without necessarily enabling subtree controls; explicit
activation within the owned empty parent corrected that assumption.

`network-policy/daemon_systemd_acceptance.py` additionally compiles the real
runner and authenticated non-root probe client. With an explicit twice-built
UID994/GID981 image/manifest, pinned runsc and a new image built from
`measured-daemon-systemd.Dockerfile`, it provisions a **new disposable guest**,
an actual 8 GiB ext4 volume and the exact production launcher/templates. Three
start/probe/stop cycles must pass idle, secrets and immutable maximum-policy
checks as UID994. Socket removal, empty retired journals/bundles, and exact owned
mount/loop/cgroup/container cleanup are required. The first real-daemon run
correctly refused loosely chosen aggregate limits; deriving the exact existing
eight-control contract corrected provisioning, without weakening the daemon.

Each cycle now starts with the worker manager and all three owned mounts stopped
and a deliberately stale **private** loop alias. Required mounts must start and the native pre-start
phase must repair that alias before authenticated daemon readiness succeeds.
No global loop device is modified through the stale alias. The controller-only
resource fixture explicitly omits this phase because it has synthetic tmpfs
mounts and no real boot plan; it is not cold-start evidence.

On 2026-09-17, the three actual cold-mount cycles and the signed-update,
health-rollback and interrupted-config recovery fixture passed with root image
`9f9b1b3e9812f6fc1e28d872aebe406a8fba22257cdc53d9ebfb0a1632493ec9` and
runsc `456ea862b62b48bb7ff27ae38c262b52315bf3d68ea0733164e4817cadc518a1`.
The local fixture runner was
`ab0b49748fa7fadee7071d639b7cbf3413c1772daaa9ddb67085878fe2c9d747`;
client `255a3fc2d2eebf9aafb705414d0c1a7642f6ac8f9e1840cbe6a7c67591fe04dc`.
Owned mounts, loops, groups and the disposable container were removed. These
are local acceptance observations, not a released runner attestation or physical
production-host reboot.

This test loads only synthetic public trust material and no gateway credentials.
It is startup/restart readiness, not job execution, physical host reboot, real
gateway/DB/object-storage integration or production activation. Real Paper with
the candidate image and noexec staging has separate acceptance evidence. Live
activation still requires a fresh coordinator drain, matching backend/runner
capability and image policy, signed runner installation, verified unit ordering,
concrete network provisioning and end-to-end execution/recovery evidence.
