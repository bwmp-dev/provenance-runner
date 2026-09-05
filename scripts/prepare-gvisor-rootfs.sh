#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'usage: %s {prepare|verify|release} /absolute/rootfs\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
action=$1
rootfs=$2
[[ "$action" == prepare || "$action" == verify || "$action" == release ]] || usage
[[ "$rootfs" == /* && "$rootfs" != / ]] || {
  printf 'root filesystem must be an absolute path other than /\n' >&2
  exit 2
}
[[ -d "$rootfs" && ! -L "$rootfs" ]] || {
  printf 'root filesystem must be an existing non-symbolic-link directory: %s\n' "$rootfs" >&2
  exit 2
}
resolved_rootfs=$(realpath -e -- "$rootfs")
[[ "$resolved_rootfs" == "$rootfs" ]] || {
  printf 'root filesystem path must be canonical and contain no symbolic-link components: %s\n' "$rootfs" >&2
  exit 2
}
rootfs_uid=$(stat -c '%u' -- "$rootfs")
rootfs_gid=$(stat -c '%g' -- "$rootfs")

rootfs_tree_sha256() {
  tar --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cf - -C "$rootfs" . | sha256sum | cut -d' ' -f1
}

require_directory() {
  local path=$1
  local mode=$2
  [[ ! -L "$path" && -d "$path" ]] || {
    printf 'required root filesystem mount target is not a non-symbolic-link directory: %s\n' "$path" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$path") == "$mode" ]] || {
    printf 'root filesystem mount target %s has mode %s, want %s\n' "$path" "$(stat -c '%a' -- "$path")" "$mode" >&2
    exit 1
  }
  [[ $(stat -c '%u:%g' -- "$path") == "$rootfs_uid:$rootfs_gid" ]] || {
    printf 'root filesystem mount target %s has owner %s, want %s:%s\n' "$path" "$(stat -c '%u:%g' -- "$path")" "$rootfs_uid" "$rootfs_gid" >&2
    exit 1
  }
}

require_rootfs() {
  [[ ! -L "$rootfs" && -d "$rootfs" ]] || {
    printf 'root filesystem is not a non-symbolic-link directory: %s\n' "$rootfs" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$rootfs") == 711 ]] || {
    printf 'root filesystem %s has mode %s, want 711\n' "$rootfs" "$(stat -c '%a' -- "$rootfs")" >&2
    exit 1
  }
  [[ $(stat -c '%u:%g' -- "$rootfs") == "$rootfs_uid:$rootfs_gid" ]] || {
    printf 'root filesystem %s owner changed during preparation\n' "$rootfs" >&2
    exit 1
  }
}

require_expected_children() {
  local path=$1
  shift
  local entry allowed child
  while IFS= read -r -d '' entry; do
    child=${entry##*/}
    allowed=false
    for expected in "$@"; do
      if [[ "$child" == "$expected" ]]; then
        allowed=true
        break
      fi
    done
    [[ "$allowed" == true ]] || {
      printf 'refusing nonempty legacy root filesystem mount target %s (unexpected entry %s)\n' "$path" "$child" >&2
      exit 1
    }
  done < <(find "$path" -mindepth 1 -maxdepth 1 -print0)
}

prepare_directory() {
  local path=$1
  local mode=$2
  shift 2
  if [[ -L "$path" || ( -e "$path" && ! -d "$path" ) ]]; then
    printf 'refusing unsafe existing root filesystem mount target: %s\n' "$path" >&2
    exit 1
  fi
  if [[ ! -e "$path" ]]; then
    local parent
    parent=$(dirname -- "$path")
    [[ "$parent" == "$rootfs" ]] || require_directory "$parent" 700
    install --directory --mode="$mode" --owner="$rootfs_uid" --group="$rootfs_gid" -- "$path"
  fi
  require_expected_children "$path" "$@"
  chown "$rootfs_uid:$rootfs_gid" -- "$path"
  chmod "$mode" -- "$path"
  require_directory "$path" "$mode"
}

normalize_optional_empty_directory() {
  local path=$1
  local mode=$2
  [[ ! -L "$path" ]] || {
    printf 'refusing symbolic-link inherited root filesystem entry: %s\n' "$path" >&2
    exit 1
  }
  [[ -e "$path" ]] || return 0
  [[ -d "$path" ]] || {
    printf 'refusing wrong-type inherited root filesystem entry: %s\n' "$path" >&2
    exit 1
  }
  require_expected_children "$path"
  chown "$rootfs_uid:$rootfs_gid" -- "$path"
  chmod "$mode" -- "$path"
  require_directory "$path" "$mode"
}

normalize_optional_empty_file() {
  local path=$1
  local mode=$2
  [[ ! -L "$path" ]] || {
    printf 'refusing symbolic-link inherited root filesystem entry: %s\n' "$path" >&2
    exit 1
  }
  [[ -e "$path" ]] || return 0
  [[ -f "$path" && $(stat -c '%s' -- "$path") == 0 ]] || {
    printf 'refusing nonempty or wrong-type inherited root filesystem entry: %s\n' "$path" >&2
    exit 1
  }
  chown "$rootfs_uid:$rootfs_gid" -- "$path"
  chmod "$mode" -- "$path"
}

require_event_placeholder() {
  local path=$rootfs/tmp/provenance-probe-events.ndjson
  [[ ! -L "$path" && -f "$path" ]] || {
    printf 'structured-event mount target is not a non-symbolic-link regular file: %s\n' "$path" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$path") == 600 ]] || {
    printf 'structured-event mount target %s has mode %s, want 600\n' "$path" "$(stat -c '%a' -- "$path")" >&2
    exit 1
  }
  [[ $(stat -c '%s' -- "$path") == 0 ]] || {
    printf 'structured-event mount target must be empty: %s\n' "$path" >&2
    exit 1
  }
  [[ $(stat -c '%u:%g' -- "$path") == "$rootfs_uid:$rootfs_gid" ]] || {
    printf 'structured-event mount target %s has owner %s, want %s:%s\n' "$path" "$(stat -c '%u:%g' -- "$path")" "$rootfs_uid" "$rootfs_gid" >&2
    exit 1
  }
}

require_layout() {
  require_rootfs
  for inherited in proc dev dev/pts; do
    require_directory "$rootfs/$inherited" 700
  done
  require_directory "$rootfs/inputs" 700
  require_directory "$rootfs/runtime" 700
  require_directory "$rootfs/workspace" 700
  require_directory "$rootfs/tmp" 1700
  require_event_placeholder
}

require_read_only_mount() {
  mountpoint --quiet -- "$rootfs" || {
    printf 'root filesystem is not an exact mountpoint: %s\n' "$rootfs" >&2
    exit 1
  }
  findmnt --noheadings --mountpoint "$rootfs" --output OPTIONS \
    | tr ',' '\n' | grep --fixed-strings --line-regexp ro >/dev/null || {
      printf 'root filesystem mount is not read-only: %s\n' "$rootfs" >&2
      exit 1
    }
}

require_no_descendant_mounts() {
  local target
  while IFS= read -r target; do
    [[ "$target" == "$rootfs" ]] && continue
    printf 'refusing to release root filesystem with descendant mount: %s\n' "$target" >&2
    exit 1
  done < <(findmnt --submounts --raw --noheadings --output TARGET --mountpoint "$rootfs")
}

report_rootfs_holders() {
  local reference target
  for reference in /proc/[0-9]*/cwd /proc/[0-9]*/root /proc/[0-9]*/exe /proc/[0-9]*/fd/*; do
    target=$(readlink -- "$reference" 2>/dev/null) || continue
    case "$target" in
      "$rootfs"|"$rootfs"/*)
        printf 'root filesystem holder reference: %s -> %s\n' "$reference" "$target" >&2
        ;;
    esac
  done
}

case "$action" in
  prepare)
    [[ $(id -u) -eq 0 ]] || {
      printf 'preparing a read-only root filesystem bind mount requires root\n' >&2
      exit 2
    }
    if mountpoint --quiet -- "$rootfs"; then
      require_layout
      require_read_only_mount
      rootfs_tree_sha256
      exit 0
    fi
    # Normalize exported image content for the unprivileged guest without
    # retaining any group/other write bit from the source archive.
    chmod --recursive go-rwx -- "$rootfs"
    chmod --recursive a+rX -- "$rootfs"
    chown "$rootfs_uid:$rootfs_gid" -- "$rootfs"
    chmod 0711 -- "$rootfs"
    prepare_directory "$rootfs/proc" 700
    prepare_directory "$rootfs/dev" 700 console pts shm
    prepare_directory "$rootfs/dev/pts" 700
    normalize_optional_empty_directory "$rootfs/dev/shm" 700
    normalize_optional_empty_file "$rootfs/dev/console" 700
    prepare_directory "$rootfs/inputs" 700
    prepare_directory "$rootfs/runtime" 700
    prepare_directory "$rootfs/workspace" 700
    [[ ! -L "$rootfs/tmp" && -d "$rootfs/tmp" ]] || {
      printf 'root filesystem /tmp is not a non-symbolic-link directory\n' >&2
      exit 1
    }
    require_expected_children "$rootfs/tmp" provenance-probe-events.ndjson
    chown "$rootfs_uid:$rootfs_gid" -- "$rootfs/tmp"
    chmod 1700 -- "$rootfs/tmp"
    event_target=$rootfs/tmp/provenance-probe-events.ndjson
    if [[ -L "$event_target" || ( -e "$event_target" && ! -f "$event_target" ) ]]; then
      printf 'refusing unsafe existing structured-event mount target: %s\n' "$event_target" >&2
      exit 1
    fi
    if [[ ! -e "$event_target" ]]; then
      install --mode=0600 --owner="$rootfs_uid" --group="$rootfs_gid" /dev/null "$event_target"
    fi
    [[ $(stat -c '%s' -- "$event_target") == 0 ]] || {
      printf 'refusing nonempty structured-event mount target: %s\n' "$event_target" >&2
      exit 1
    }
    chown "$rootfs_uid:$rootfs_gid" -- "$event_target"
    chmod 0600 -- "$event_target"
    require_layout
    before=$(rootfs_tree_sha256)
    mount --bind -- "$rootfs" "$rootfs"
    if ! mount --options remount,bind,ro -- "$rootfs"; then
      umount -- "$rootfs"
      exit 1
    fi
    require_read_only_mount
    require_layout
    after=$(rootfs_tree_sha256)
    [[ "$after" == "$before" ]] || {
      printf 'root filesystem identity changed while establishing read-only bind mount\n' >&2
      exit 1
    }
    printf '%s\n' "$after"
    ;;
  verify)
    require_read_only_mount
    require_layout
    rootfs_tree_sha256
    ;;
  release)
    [[ $(id -u) -eq 0 ]] || {
      printf 'releasing a read-only root filesystem bind mount requires root\n' >&2
      exit 2
    }
    require_read_only_mount
    require_no_descendant_mounts
    released=false
    for _ in $(seq 1 100); do
      if umount -- "$rootfs" 2>/dev/null; then
        released=true
        break
      fi
      sleep 0.1
    done
    if [[ "$released" != true ]]; then
      printf 'root filesystem remains busy after bounded release retries: %s\n' "$rootfs" >&2
      findmnt --submounts --raw --noheadings --output TARGET,OPTIONS --mountpoint "$rootfs" >&2 || true
      report_rootfs_holders
      umount -- "$rootfs"
    fi
    if mountpoint --quiet -- "$rootfs"; then
      printf 'root filesystem remains mounted after release: %s\n' "$rootfs" >&2
      exit 1
    fi
    ;;
esac
