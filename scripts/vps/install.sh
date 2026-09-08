#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo or as root.' >&2; exit 1; }
cd "$(dirname "$0")"
exec python3 ./install.py "$@"
