#!/usr/bin/env bash
# A fresh disposable user manager and image; never the production runner host.
set -euo pipefail
umask 077
[[ $(id -u) == 0 && ( $# == 7 || $# == 8 ) ]]
[[ ${GITHUB_ACTIONS:-} == true && ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_JOB:-} == gvisor-smoke ]]
runsc=$1 source_archive=$2 source_sha=$3 builder=$4 builder_sha=$5 test_binary=$6 evidence=$7
libraries=${8:-}
[[ "$source_sha" =~ ^[a-f0-9]{64}$ && "$builder_sha" =~ ^[a-f0-9]{64}$ ]]
for input in "$runsc" "$source_archive" "$builder" "$test_binary"; do
  [[ "$input" == /* && -f "$input" && ! -L "$input" ]]
done
[[ "$evidence" == /* && ! -e "$evidence" && ! -L "$evidence" ]]
for prerequisite in systemctl systemd-run useradd userdel setpriv losetup mount umount mountpoint python3 jq timeout pgrep getent sha256sum apparmor_parser; do
  command -v "$prerequisite" >/dev/null || { echo "missing measured fixture prerequisite: $prerequisite" >&2; exit 1; }
done
builder_environment=(env -u LD_PRELOAD -u LD_AUDIT -u LD_LIBRARY_PATH)
if [[ -n "$libraries" ]]; then
  python3 - "$libraries" <<'PY'
import os, stat, sys
from pathlib import Path
p = Path(sys.argv[1])
assert p.is_absolute() and p.resolve() == p
for value in (p, *p.parents):
    s = value.lstat()
    assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_mode & 0o022 == 0
for value in p.iterdir():
    s = value.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_mode & 0o022 == 0
PY
  builder_environment+=("LD_LIBRARY_PATH=$libraries")
fi
[[ $(ps -p 1 -o comm=) == systemd ]]
fixture=$(mktemp -d /var/lib/provenance-measurement-ci.XXXXXXXX)
task_user="pvm$(basename "$fixture" | tr -cd 'a-zA-Z0-9' | tail -c 9 | tr 'A-Z' 'a-z')"
task_uid= task_gid= user_created=0 manager_started=0 loop= image= monitor_pid= root_mounted=0 evidence_created=0 cleanup_error=0
source "$(dirname "$0")/measured-runtime-profile.sh"
cleanup() {
  result=$?
  trap - EXIT
  set +e
  clean=$((1 - cleanup_error))
  if [[ -n "$monitor_pid" ]]; then
    touch "$fixture/monitor-stop" || clean=0
    for attempt in {1..50}; do
      kill -0 "$monitor_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$monitor_pid" 2>/dev/null; then
      kill -TERM "$monitor_pid" 2>/dev/null
      sleep 0.1
      kill -KILL "$monitor_pid" 2>/dev/null
      clean=0
    fi
    wait "$monitor_pid"
    monitor_result=$?
    [[ "$monitor_result" == 0 ]] || result=1
  fi
  if [[ "$manager_started" == 1 ]]; then
    timeout 30s systemctl stop "user@${task_uid}.service" || clean=0
    timeout 30s systemctl stop "user-runtime-dir@${task_uid}.service" || clean=0
    systemctl is-active --quiet "user@${task_uid}.service" && clean=0
    [[ ! -e "/run/user/$task_uid" ]] || clean=0
  fi
  if [[ "$root_mounted" == 1 ]]; then
    umount "$fixture/rootfs" || clean=0
    mountpoint -q "$fixture/rootfs" && clean=0
  fi
  if [[ -n "$loop" ]]; then
    if [[ $(losetup --noheadings --output BACK-FILE "$loop") == "$image" ]]; then
      losetup --detach "$loop" || clean=0
      [[ -z $(losetup --noheadings --output NAME --associated "$image") ]] || clean=0
    else clean=0; fi
  fi
  profile_remove || clean=0
  if [[ "$user_created" == 1 && "$profile_loaded" == 0 && "$profile_uncertain" == 0 ]]; then
    if [[ $(id -u "$task_user") == "$task_uid" ]] && ! pgrep -u "$task_uid" >/dev/null; then
      userdel "$task_user" || clean=0
      # useradd --user-group created this group. Do not delete a surviving
      # group implicitly: retain its exact identity for operator diagnosis.
      getent group "$task_gid" >/dev/null && clean=0
      getent passwd "$task_uid" >/dev/null && clean=0
    else clean=0; fi
  fi
  if [[ "$evidence_created" != 1 ]]; then
    echo "measured fixture evidence creation failed; retained target: $fixture" >&2
    exit 1
  fi
  jq -n --arg name "$profile_name" --arg sha256 "$profile_sha" --arg status "$profile_status" \
    --argjson loaded "$profile_loaded" --argjson uncertain "$profile_uncertain" \
    --argjson loadSucceeded "$profile_load_succeeded" --argjson zeroProcesses "$profile_zero_processes" \
    '{version:1,name:$name,sha256:$sha256,status:$status,loaded:($loaded==1),uncertain:($uncertain==1),loadSucceeded:($loadSucceeded==1),zeroOwnedProcessesBeforeRemoval:($zeroProcesses==1)}' > "$evidence/profile.json" || clean=0
  if [[ -n "$profile_file" && -f "$profile_file" && ! -L "$profile_file" ]]; then
    cp -- "$profile_file" "$evidence/profile.txt" || clean=0
  fi
  jq -n --arg user "$task_user" --arg uid "$task_uid" --arg gid "$task_gid" --arg loop "$loop" --arg fixture "$fixture" --argjson clean "$clean" --argjson result "$result" \
    '{version:1,disposableUser:$user,disposableUid:$uid,disposableGid:$gid,allocatedLoop:$loop,fixturePath:$fixture,cleanupSucceeded:($clean==1),testExit:$result}' > "$evidence/cleanup.json" || clean=0
  evidence_owner=${SUDO_UID:-0}
  [[ "$evidence_owner" =~ ^[0-9]+$ ]] || exit 1
  chown "$evidence_owner" "$evidence" || clean=0
  (cd "$evidence" && shopt -s nullglob && sha256sum -- *.json *.log *.txt > manifest.sha256) || clean=0
  for record in cleanup.json image.json smoke.log executable-observations.json monitor.log preflight.json exec-probe.log profile.json profile.txt manifest.sha256; do
    if [[ -f "$evidence/$record" && ! -L "$evidence/$record" ]]; then chown "$evidence_owner" "$evidence/$record" || clean=0; fi
  done
  # Never erase a failed cleanup target. Keep it for exact operator diagnosis.
  if [[ "$clean" == 1 && "$fixture" =~ ^/var/lib/provenance-measurement-ci\.[A-Za-z0-9]{8}$ ]]; then
    rm -rf -- "$fixture" || clean=0
  fi
  [[ "$clean" == 1 ]] || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
chmod 0711 "$fixture"
mkdir -m 0700 "$evidence"
evidence_created=1
! getent passwd "$task_user" >/dev/null
# Use an absent identity, never a manager belonging to an existing user.
for attempt in {1..32}; do
  candidate=$((60000 + RANDOM % 4000))
  if ! getent passwd "$candidate" >/dev/null && ! getent group "$candidate" >/dev/null && ! pgrep -u "$candidate" >/dev/null && [[ ! -e "/run/user/$candidate" ]] && ! systemctl is-active --quiet "user@$candidate.service"; then task_uid=$candidate; break; fi
done
[[ "$task_uid" =~ ^[0-9]+$ ]]
useradd --uid "$task_uid" --user-group --no-create-home --home-dir "$fixture/home" --shell /bin/sh "$task_user"
user_created=1
[[ $(id -u "$task_user") == "$task_uid" ]]
task_gid=$(id -g "$task_user")
chown "0:$task_gid" "$fixture"
chmod 0710 "$fixture"
mkdir -m 0700 "$fixture/home" "$fixture/work"
chown "$task_uid:$task_gid" "$fixture/home" "$fixture/work"
mkdir -m 0711 "$fixture/rootfs"
"${builder_environment[@]}" PYTHONDONTWRITEBYTECODE=1 TMPDIR="$fixture" PATH="$(dirname "$builder"):$PATH" \
  python3 "$(dirname "$0")/test_build_measured_rootfs.py"
"${builder_environment[@]}" python3 "$(dirname "$0")/build-measured-rootfs.py" --source "$source_archive" --source-sha256 "$source_sha" \
  --builder "$builder" --builder-sha256 "$builder_sha" --output "$fixture/images" --uid "$task_uid" --gid "$task_gid" > "$evidence/image.json"
image="$fixture/images/sha256-$(jq -er .sha256 "$evidence/image.json").squashfs"
chmod 0711 "$fixture/images"
chmod 0444 "$image"
loop=$(losetup --find --show --read-only "$image")
[[ "$loop" =~ ^/dev/loop[0-9]+$ && $(losetup --noheadings --output BACK-FILE "$loop") == "$image" ]]
# Grant access through a NEW private node, never chmod an existing /dev node.
minor=$(stat -c '%T' "$loop")
mknod -m 0444 "$fixture/loop" b 7 "$((16#$minor))"
mount -t squashfs -o ro,nosuid,nodev "$loop" "$fixture/rootfs"
root_mounted=1
install -o 0 -g "$task_gid" -m 0550 "$test_binary" "$fixture/gvisor-smoke.test"
profile_prepare
profile_load
! systemctl is-active --quiet "user@${task_uid}.service"
if systemctl start "user@${task_uid}.service"; then
  manager_started=1
else
  # Only this successfully created disposable account can own this manager.
  # A failed start may still leave resources; retain targets if stop fails.
  timeout 30s systemctl stop "user@${task_uid}.service" || cleanup_error=1
  timeout 30s systemctl stop "user-runtime-dir@${task_uid}.service" || cleanup_error=1
  exit 1
fi
session_env=("HOME=$fixture/home" "XDG_RUNTIME_DIR=/run/user/$task_uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$task_uid/bus")
setpriv --reuid "$task_uid" --regid "$task_gid" --clear-groups env "${session_env[@]}" \
  systemd-run --user --scope --quiet --unit=pvm-preflight -- true
scope_root="/sys/fs/cgroup/user.slice/user-${task_uid}.slice/user@${task_uid}.service/app.slice"
[[ -d "$scope_root" ]]
install -m 0555 "$(dirname "$0")/measured-runtime-preflight.py" "$fixture/preflight.py"
setpriv --reuid "$task_uid" --regid "$task_gid" --clear-groups env "${session_env[@]}" \
  systemd-run --user --scope --collect --quiet --slice=app.slice --unit=pvm-diagnostics \
    python3 "$fixture/preflight.py" > "$evidence/preflight.json"
setpriv --reuid "$task_uid" --regid "$task_gid" --clear-groups env "${session_env[@]}" PROVENANCE_MEASURED_EXEC_DIAGNOSTIC=1 \
  systemd-run --user --scope --collect --quiet --slice=app.slice --unit=pvm-execdiag \
    "$fixture/gvisor-smoke.test" -test.run '^TestMeasured(NamespaceExec|NativeFDExec)Diagnostic$' -test.v -test.count=1 > "$evidence/exec-probe.log" 2>&1
python3 "$(dirname "$0")/measured-runtime-monitor.py" --uid "$task_uid" \
  --scope-root "${scope_root#/sys/fs/cgroup}" --frontend "$runsc" \
  --stop-file "$fixture/monitor-stop" --output "$evidence/executable-observations.json" \
  > "$evidence/monitor.log" 2>&1 &
monitor_pid=$!
setpriv --reuid "$task_uid" --regid "$task_gid" --clear-groups env "${session_env[@]}" \
  TMPDIR="$fixture/work" PROVENANCE_RUNSC_SMOKE=1 PROVENANCE_RUNSC_PATH="$runsc" \
  PROVENANCE_RUNSC_ROOTFS="$fixture/rootfs" PROVENANCE_MEASURED_ROOTFS_IMAGE="$image" \
  PROVENANCE_MEASURED_LOOP_DEVICE="$fixture/loop" \
  PROVENANCE_MEASURED_RUNTIME_MODE=embedded-executable \
  PROVENANCE_GVISOR_CGROUP_DRIVER=systemd-user PROVENANCE_SYSTEMD_RUN_PATH="$(command -v systemd-run)" \
  PROVENANCE_SYSTEMD_CGROUP_ROOT="$scope_root" \
  systemd-run --user --scope --collect --quiet --slice=app.slice --unit=pvm-driver \
    timeout --foreground 180s "$fixture/gvisor-smoke.test" -test.run '^TestRunscSmoke$' -test.count=1 -test.v -test.timeout=150s > "$evidence/smoke.log" 2>&1
