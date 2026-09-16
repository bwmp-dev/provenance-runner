# Signed updates with a measured root controller

The hosted updater continues to require its existing signed release, backend
drain/operation identity, quiet worker journal, retained binary and post-start
health acknowledgements. With measured provisioning installed, a worker binary
is no longer the only mutable object: the root daemon configuration pins that
binary and its launch plan pins both binary and configuration.

Before stopping anything, the updater checks the current bindings and every
launch input, verifies that the worker wrapper requires measured-controller
readiness, and durably retains exact before/after configuration and launch-plan
bytes beneath the existing root-only update directory. The only after-image
changes are the runner digest and the resulting configuration digest. Network
policy, image, tools, identities, paths, secrets and other operator inputs are
not re-derived or broadened. Interrupted staging can reuse only identical files.

Stopping first retires the worker and then explicitly waits for the root daemon.
The root service must be inactive/failed with its owned cgroup gone before binary
replacement; the user manager's empty scope list is not sufficient. Replacement
then writes the binary, installed metadata, daemon configuration and launch plan
atomically, one file at a time. A transient mixed state cannot start the pinned
daemon. Recovery accepts only the recorded old/new bytes and restores the exact
old projection while admission remains drained. An unrelated operator edit,
corrupt snapshot, unexpected binary, live root cgroup or partially installed
measured configuration refuses instead of being overwritten.

Without measured provisioning, the existing hosted update path is unchanged.
Catalog transactions also wait for the root daemon when stopping but do not
alter its binary/configuration bindings. First measured activation must install
the signed binary before introducing its pinned launch configuration; subsequent
binary updates use this transaction. The wrapper's controller dependency is an
installation requirement, not silently added by the updater.

## Evidence scope

Unit tests cover all eight binary/configuration/plan before/after combinations,
interruptions following each of the four atomic writes, retained-byte corruption,
unknown operator edits, missing dependency/transaction and unretired groups.

`network-policy/daemon_systemd_acceptance.py --updater` extends the explicit
hosted-image fixture with actual Ed25519 signing/verification, real systemd and
the real root daemon. Distinct test ELF bytes use an appended fixture marker,
not different program behavior. Successful install, health-triggered rollback
and a simulated process death after configuration replacement must all recover
and pass authenticated non-root daemon probes. Root groups, mounts and loops
must be retired before successful container removal.

The coordinator replies, accelerated health sampling and worker wrapper are
synthetic; the worker process, gateway/database/object-storage path and production
deployment are **not** covered by this fixture. No real credentials are loaded,
and neither signatures nor root pin checks are bypassed. Live update/recovery
acceptance remains part of coordinated activation.
