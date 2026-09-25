#!/usr/bin/env bash
# WP-11C consolidated hostile fixture re-run.
#
# Single documented entry point that re-runs every hostile fixture in this
# repository: the Go hostile-input boundary tests and fuzz seed corpora, the
# Plan 03 acceptance contract checks, and — when a prepared gVisor host is
# available — the real-runsc containment smoke and the in-sandbox isolation
# probe. It never contacts production: sandbox probes target only well-known
# private/metadata addresses from inside a network=none sandbox.
#
# Usage:
#   scripts/hostile-fixtures.sh              # host-safe tiers (default)
#   scripts/hostile-fixtures.sh --fuzz [dur] # also run bounded native fuzzing
#   scripts/hostile-fixtures.sh --gvisor     # also run the real-runsc tiers
#   scripts/hostile-fixtures.sh --all [dur]  # everything
#
# The real-runsc tiers require a prepared read-only root filesystem mount and
# gVisor; export before running (see docs/security/hostile-fixture-inventory.md):
#   PROVENANCE_RUNSC_SMOKE=1
#   PROVENANCE_RUNSC_PATH=/path/to/runsc
#   PROVENANCE_RUNSC_ROOTFS=/path/to/readonly-rootfs
#
# The full Plan 03 Paper/gVisor hostile matrix (memory/PID/disk bombs, network
# scan, metadata endpoint, log flood, the isolation-probe Paper JAR) is driven
# by scripts/plan03-acceptance.sh under the workflow_dispatch gate and is not
# re-implemented here.
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repository_root"

run_fuzz=false
run_gvisor=false
fuzztime="20s"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fuzz) run_fuzz=true ;;
    --gvisor) run_gvisor=true ;;
    --all) run_fuzz=true; run_gvisor=true ;;
    [0-9]*s|[0-9]*m) fuzztime="$1" ;;
    -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

section() { printf '\n=== %s ===\n' "$1"; }

# Curated hostile-input boundary tests exercised under the race detector. These
# assert fail-closed behavior and product-vs-infrastructure classification at
# every runner-side boundary that receives hostile material.
hostile_test_pattern='Hostile|FailsClosed|FailClosed|Unsafe|Unbounded|Traversal|Escape|Bomb|Flood|Redact|Redaction|Metadata|Docker|Symlink|HardLink|Malformed|OpaqueReadOnly|JobInputsNever|ManagementOrMetadata|IsolationProbe|BoundsHostile|Bounded|RejectsHostile|OfferFilenameControl|StrictCodecRefuses'

section "Go hostile-input boundary tests (-race)"
go test -race \
  ./internal/provider/gvisor/... \
  ./internal/gatewayclient/... \
  ./internal/networkpolicy/... \
  ./internal/evidence/... \
  ./internal/workspace/... \
  ./internal/artifact/... \
  ./internal/localjob/... \
  ./internal/testsecrets/... \
  ./cmd/... \
  -run "$hostile_test_pattern" -count=1

section "Fuzz seed corpora (fast, no new inputs)"
fuzz_targets=(
  "./internal/provider/gvisor|FuzzGVisorJobConfiguration"
  "./internal/gatewayclient|FuzzValidateOffer"
  "./internal/gatewayclient|FuzzStrictGatewayCodecAndHandlers"
  "./internal/gatewayclient|FuzzLiveLogChunkSize"
  "./internal/networkpolicy|FuzzBinderPublicAddress"
  "./internal/networkpolicy|FuzzWorkloadDNSBoundedWire"
  "./internal/networkpolicy|FuzzDNSResponse"
  "./internal/evidence|FuzzRedactionChunkIndependent"
  "./internal/testsecrets|FuzzSecretSelectionBoundedJSON"
)
for entry in "${fuzz_targets[@]}"; do
  pkg=${entry%%|*}; fn=${entry##*|}
  go test "$pkg" -run "^$fn\$" -count=1 >/dev/null
  printf 'seed corpus ok: %s %s\n' "$pkg" "$fn"
done

if [[ "$run_fuzz" == true ]]; then
  section "Bounded native fuzzing (${fuzztime} per target)"
  for entry in "${fuzz_targets[@]}"; do
    pkg=${entry%%|*}; fn=${entry##*|}
    printf -- '--- fuzzing %s %s\n' "$pkg" "$fn"
    go test "$pkg" -run '^$' -fuzz="^$fn\$" -fuzztime="$fuzztime" -fuzzminimizetime=200x
  done
fi

section "Plan 03 acceptance contract checks (host-safe)"
scripts/plan03-acceptance.sh --contract-test

if [[ "$run_gvisor" == true ]]; then
  if [[ "${PROVENANCE_RUNSC_SMOKE:-}" != "1" || -z "${PROVENANCE_RUNSC_ROOTFS:-}" ]]; then
    printf 'skipping real-runsc tiers: set PROVENANCE_RUNSC_SMOKE=1 and PROVENANCE_RUNSC_ROOTFS\n' >&2
    printf 'these tiers need a prepared read-only rootfs mount and gVisor (self-hosted CI runner)\n' >&2
    exit 0
  fi
  section "Real-runsc containment smoke and isolation probe"
  go test ./internal/provider/gvisor \
    -run '^TestRunscSmoke$|^TestIsolationProbeSandboxDeniesEscapes$' \
    -count=1 -v -timeout=180s
fi

section "Hostile fixtures complete"
