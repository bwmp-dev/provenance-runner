#!/usr/bin/env bash
# Sourced only by the root-owned disposable CI fixture; never a host installer.
profile_loaded=0 profile_uncertain=0 profile_status=not_loaded
profile_name= profile_file= profile_sha=
profile_load_succeeded=0 profile_zero_processes=0

profile_present() {
  [[ -r /sys/kernel/security/apparmor/profiles ]] || return 2
  local line
  while IFS= read -r line; do
    [[ "$line" == "$profile_name ("* ]] && return 0
  done < /sys/kernel/security/apparmor/profiles
  return 1
}

profile_prepare() {
  [[ "$fixture" =~ ^/var/lib/provenance-measurement-ci\.[A-Za-z0-9]{8}$ ]]
  [[ "$task_gid" =~ ^[0-9]+$ && "$task_uid" =~ ^[0-9]+$ ]]
  profile_name="pvm-measured-${fixture##*.}"
  profile_file="$fixture/apparmor.profile"
  python3 - "$fixture" "$task_uid" "$task_gid" <<'PY'
import grp, os, pwd, stat, sys
from pathlib import Path
p, uid, gid = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
assert grp.getgrgid(gid).gr_mem == []
assert [x.pw_uid for x in pwd.getpwall() if x.pw_gid == gid] == [uid]
for parent in p.parents:
    s = parent.lstat()
    assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_mode & 0o022 == 0
for target, mode, kind in [(p, 0o710, stat.S_ISDIR), (p/'gvisor-smoke.test', 0o550, stat.S_ISREG)]:
    s = target.lstat()
    assert kind(s.st_mode) and s.st_uid == 0 and s.st_gid == gid and stat.S_IMODE(s.st_mode) == mode
    if kind == stat.S_ISREG:
        assert s.st_nlink == 1
        with target.open('rb') as f:
            assert f.read(4) == b'\x7fELF'
text = f'abi <abi/4.0>,\nprofile pvm-measured-{p.name.rsplit(".",1)[1]} "{p}/gvisor-smoke.test" flags=(unconfined) {{\n  userns,\n}}\n'
fd = os.open(p/'apparmor.profile', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
with os.fdopen(fd, 'w') as f:
    f.write(text)
PY
  profile_sha=$(sha256sum "$profile_file")
  profile_sha=${profile_sha%% *}
  timeout --kill-after=5s 15s apparmor_parser --skip-cache --skip-kernel-load "$profile_file"
}

profile_load() {
  local state=0
  profile_present || state=$?
  [[ "$state" == 1 ]] || { profile_status=collision_or_unavailable; profile_uncertain=1; return 1; }
  # An interrupted or failed add can have changed kernel state. Never adopt or
  # remove an uncertain profile, and never erase its protected attachment.
  profile_uncertain=1
  profile_status=add_uncertain
  timeout --kill-after=5s 15s apparmor_parser --skip-cache --add "$profile_file" || return 1
  profile_loaded=1
  profile_load_succeeded=1
  profile_uncertain=0
  profile_status=loaded
  profile_present
}

profile_remove() {
  [[ "$profile_uncertain" == 0 ]] || return 1
  [[ "$profile_loaded" == 1 ]] || return 0
  # Only absence (pgrep exit1), not a query error, authorizes removal.
  local state=0
  pgrep -u "$task_uid" >/dev/null || state=$?
  [[ "$state" == 1 ]] || { profile_status=processes_or_query_error; return 1; }
  profile_zero_processes=1
  profile_present || { profile_status=owned_profile_missing; return 1; }
  [[ $(sha256sum "$profile_file") == "$profile_sha  $profile_file" ]] || return 1
  timeout --kill-after=5s 15s apparmor_parser --skip-cache --remove "$profile_file" || { profile_status=remove_failed; return 1; }
  state=0
  profile_present || state=$?
  [[ "$state" == 1 ]] || { profile_status=remove_unverified; return 1; }
  profile_loaded=0
  profile_status=removed
}
