#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
fixture_manifest="$repository_root/testdata/plan03/fixtures.tsv"
pid_result_contract='
  def first_sequence(condition):
    first(.structuredEvents[] | select(condition) | .sequence);
  first_sequence(.kind=="PLUGIN_STATE" and .payload.name=="ProvenanceForkPidBomb" and .payload.loaded==true and .payload.enabled==true) as $target_enabled |
  first_sequence(.kind=="SERVER_LOADED") as $server_loaded |
  first_sequence(.kind=="STABILIZATION_STARTED" and .payload.durationMillis==30000) as $stabilization_started |
  first_sequence(.kind=="TARGET_REQUIREMENT" and .payload.role=="TARGET" and .payload.name=="ProvenanceForkPidBomb" and .payload.configured==true and .payload.loaded==true and .payload.enabled==true) as $target_requirement |
  first_sequence(.kind=="STABILIZATION_COMPLETED" and .payload.durationMillis==30000) as $stabilization_completed |
  first_sequence(.kind=="SERVER_READY" and .payload.requirementsSatisfied==true) as $server_ready |
  first_sequence(.kind=="CLEAN_SHUTDOWN_REQUESTED") as $shutdown_requested |
  first_sequence(.kind=="SERVER_STOPPED" and .payload.shutdownRequested==true) as $server_stopped |
  (.structuredEvents | length)==21 and
  ([.structuredEvents[].sequence] == [range(1;22)]) and
  ([.structuredEvents[].kind] == ["METADATA_INSPECTION","METADATA_INSPECTION","TEST_PLAN","PLUGIN_STATE","PLUGIN_STATE","PROBE_LOADED","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","SERVER_LOADED","PLUGIN_STATE","PLUGIN_STATE","STABILIZATION_STARTED","TARGET_REQUIREMENT","STABILIZATION_COMPLETED","SERVER_READY","CLEAN_SHUTDOWN_REQUESTED","PLUGIN_STATE","PLUGIN_STATE","SERVER_STOPPED"]) and
  .classification=="passed" and
  .phase=="completed" and
  (.failure // null)==null and
  .execution.exitCode==0 and
  .completeLog.state=="complete" and
  .completeLog.truncated==false and
  .cleanup.succeeded==true and
  ($target_enabled < $server_loaded) and
  ($server_loaded < $stabilization_started) and
  ($stabilization_started < $target_requirement) and
  ($target_requirement < $stabilization_completed) and
  ($stabilization_completed < $server_ready) and
  ($server_ready < $shutdown_requested) and
  ($shutdown_requested < $server_stopped)
'
pid_resource_contract='
  def pid_denials_or_null:
    (.pidsEvents // "") as $events |
    if ($events | test("^max [0-9]+;$")) then
      ($events | capture("^max (?<count>[0-9]+);$").count | tonumber)
    else
      null
    end;
  def sandbox_pids_or_null:
    if (.sandboxPIDsCurrent | type)=="number" then .sandboxPIDsCurrent else null end;
  def memory_event($name):
    (.memoryEvents | capture("(^|;)"+$name+" (?<count>[0-9]+);").count | tonumber);
  [.[] | pid_denials_or_null | select(. != null)] as $denial_observations |
  [.[] | sandbox_pids_or_null | select(. != null)] as $sandbox_observations |
  length > 0 and
  all(.[]; .pidsMax=="65") and
  all(.[]; ((.pidsEvents | type)=="string" and (.pidsEvents | test("^max [0-9]+;$")))) and
  all(.[]; (.sandboxPIDsCurrent==null or (.sandboxPIDsCurrent | type)=="number")) and
  ([.[].pidsCurrent | tonumber] | max) <= 61 and
  ($sandbox_observations | length) > 0 and
  ($sandbox_observations | max) == 48 and
  all(.[]; (.pidsCurrent | tonumber) >= 0 and (.pidsCurrent | tonumber) <= 61 and ((sandbox_pids_or_null==null) or sandbox_pids_or_null<=48)) and
  ($denial_observations | length) == length and
  all($denial_observations[]; . == 0) and
  all(.[]; memory_event("max")==0 and memory_event("oom")==0 and memory_event("oom_kill")==0)
'
pid_saturation_contract='
  def sandbox_pids_or_null:
    if (.sandboxPIDsCurrent | type)=="number" then .sandboxPIDsCurrent else null end;
  def guest_release_runs($peak):
    reduce .[] as $sample
      ({runs:[],current:[]};
       ($sample | sandbox_pids_or_null) as $guest_pids |
       if ($guest_pids==null) then
         .
       elif ($guest_pids > 2 and $guest_pids < $peak) then
         .current += [$sample]
       elif (.current | length) > 0 then
         .runs += [.current] | .current = []
       else
         .
       end) |
    if (.current | length) > 0 then .runs + [.current] else .runs end;
  . as $samples |
  ([$samples[] | sandbox_pids_or_null | select(. != null)] | max // null) as $guest_peak |
  ([range(0; $samples | length) |
    select(($samples[.] | sandbox_pids_or_null)==$guest_peak)] | first // -1) as $guest_peak_index |
  ($samples[$guest_peak_index+1:] | guest_release_runs($guest_peak)) as $guest_release_runs |
  [$guest_release_runs[] |
    select((length >= 20) and
           ((.[-1].timestampNanoseconds - .[0].timestampNanoseconds) >= 1000000000))] as $qualifying_guest_releases |
  ($guest_peak_index >= 1) and
  ($guest_peak == 48) and
  ($qualifying_guest_releases | length) > 0
'
pid_repetitions_contract='
  [.[] | select(.fixture=="fork-pid-bomb")] as $runs |
  ($runs|length)==3 and
  ($runs|map(.caseIdentity)|unique|length)==3 and
  ($runs|map(.repetition)|sort)==[1,2,3] and
  all($runs[]; .accepted==true and .cliExit==0 and .classification=="passed" and .phase=="completed" and .failureCode==null and .completeLog.state=="complete" and .completeLog.truncated==false)
'
disk_fill_result_contract='
  def first_sequence(condition):
    first(.structuredEvents[] | select(condition) | .sequence);
  first_sequence(.kind=="PLUGIN_STATE" and .payload.name=="ProvenanceDiskFill" and .payload.loaded==true and .payload.enabled==true) as $target_enabled |
  first_sequence(.kind=="SERVER_LOADED") as $server_loaded |
  first_sequence(.kind=="STABILIZATION_STARTED" and .payload.durationMillis==2000) as $stabilization_started |
  first_sequence(.kind=="TARGET_REQUIREMENT" and .payload.role=="TARGET" and .payload.name=="ProvenanceDiskFill" and .payload.configured==true and .payload.loaded==true and .payload.enabled==true) as $target_requirement |
  first_sequence(.kind=="STABILIZATION_COMPLETED" and .payload.durationMillis==2000) as $stabilization_completed |
  first_sequence(.kind=="SERVER_READY" and .payload.requirementsSatisfied==true) as $server_ready |
  first_sequence(.kind=="CLEAN_SHUTDOWN_REQUESTED") as $shutdown_requested |
  first_sequence(.kind=="SERVER_STOPPED" and .payload.shutdownRequested==true) as $server_stopped |
  (.structuredEvents | length)==21 and
  ([.structuredEvents[].sequence] == [range(1;22)]) and
  ([.structuredEvents[].kind] == ["METADATA_INSPECTION","METADATA_INSPECTION","TEST_PLAN","PLUGIN_STATE","PLUGIN_STATE","PROBE_LOADED","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","SERVER_LOADED","PLUGIN_STATE","PLUGIN_STATE","STABILIZATION_STARTED","TARGET_REQUIREMENT","STABILIZATION_COMPLETED","SERVER_READY","CLEAN_SHUTDOWN_REQUESTED","PLUGIN_STATE","PLUGIN_STATE","SERVER_STOPPED"]) and
  .classification=="passed" and
  .phase=="completed" and
  (.failure // null)==null and
  .execution.exitCode==0 and
  .completeLog.state=="complete" and
  .completeLog.truncated==false and
  .cleanup.succeeded==true and
  ($target_enabled < $server_loaded) and
  ($server_loaded < $stabilization_started) and
  ($stabilization_started < $target_requirement) and
  ($target_requirement < $stabilization_completed) and
  ($stabilization_completed < $server_ready) and
  ($server_ready < $shutdown_requested) and
  ($shutdown_requested < $server_stopped)
'
disk_fill_marker='No space left on device'
event_channel_usage_contract='
  .usage.eventChannelMaximumBytes==4194304 and
  .usage.eventChannelBufferedBytes>=0 and
  .usage.eventChannelBufferedBytes<=.usage.eventChannelMaximumBytes and
  .usage.eventChannelResourceBytes==0 and
  .usage.eventChannelOverflowed==false and
  .usage.eventChannelRemoved==true
'

validate_disk_fill_contract() {
  local result=$1 complete_log=$2
  jq -e "$disk_fill_result_contract" "$result" >/dev/null &&
    grep -Fq "$disk_fill_marker" "$complete_log"
}

fixture_repetitions() {
  [[ $1 == fork-pid-bomb ]] && printf '3\n' || printf '1\n'
}

fixture_case_identity() {
  local fixture=$1 repetition=$2
  [[ "$fixture" == fork-pid-bomb ]] && printf '%s-run-%s\n' "$fixture" "$repetition" || printf '%s\n' "$fixture"
}

complete_cgroup_sample() {
  local field
  for field in "$@"; do
    [[ -n "$field" ]] || return 1
  done
}

incomplete_cgroup_sample_is_teardown() {
  local runner_pid=$1
  ! kill -0 "$runner_pid" 2>/dev/null
}

run_contract_tests() {
  for command_name in awk grep head jq mktemp seq; do
    command -v "$command_name" >/dev/null || {
      printf '%s is required for Plan 03 contract tests\n' "$command_name" >&2
      return 2
    }
  done
  local test_root good_result good_samples good_summary good_disk_result good_disk_log rejection_status
  test_root=$(mktemp -d "${TMPDIR:-/tmp}/plan03-contract-test.XXXXXX")
  trap 'rm --recursive --force -- "$test_root"' RETURN
  good_result="$test_root/good-result.json"
  good_samples="$test_root/good-samples.ndjson"
  good_summary="$test_root/good-summary.ndjson"
  good_disk_result="$test_root/good-disk-result.json"
  good_disk_log="$test_root/good-disk.log"

  jq -n '{classification:"passed",phase:"completed",failure:null,execution:{exitCode:0},completeLog:{state:"complete",truncated:false},cleanup:{succeeded:true},structuredEvents:[
    {sequence:1,kind:"METADATA_INSPECTION",payload:{}},
    {sequence:2,kind:"METADATA_INSPECTION",payload:{}},
    {sequence:3,kind:"TEST_PLAN",payload:{}},
    {sequence:4,kind:"PLUGIN_STATE",payload:{}},
    {sequence:5,kind:"PLUGIN_STATE",payload:{}},
    {sequence:6,kind:"PROBE_LOADED",payload:{}},
    {sequence:7,kind:"PLUGIN_STATE",payload:{}},
    {sequence:8,kind:"PLUGIN_STATE",payload:{}},
    {sequence:9,kind:"PLUGIN_STATE",payload:{}},
    {sequence:10,kind:"PLUGIN_STATE",payload:{name:"ProvenanceForkPidBomb",loaded:true,enabled:true}},
    {sequence:11,kind:"SERVER_LOADED",payload:{}},
    {sequence:12,kind:"PLUGIN_STATE",payload:{}},
    {sequence:13,kind:"PLUGIN_STATE",payload:{}},
    {sequence:14,kind:"STABILIZATION_STARTED",payload:{durationMillis:30000}},
    {sequence:15,kind:"TARGET_REQUIREMENT",payload:{role:"TARGET",name:"ProvenanceForkPidBomb",configured:true,loaded:true,enabled:true}},
    {sequence:16,kind:"STABILIZATION_COMPLETED",payload:{durationMillis:30000}},
    {sequence:17,kind:"SERVER_READY",payload:{requirementsSatisfied:true}},
    {sequence:18,kind:"CLEAN_SHUTDOWN_REQUESTED",payload:{}},
    {sequence:19,kind:"PLUGIN_STATE",payload:{}},
    {sequence:20,kind:"PLUGIN_STATE",payload:{}},
    {sequence:21,kind:"SERVER_STOPPED",payload:{shutdownRequested:true}}
  ]}' > "$good_result"
  jq -e "$pid_result_contract" "$good_result" >/dev/null
  if jq -e "$pid_result_contract" >/dev/null 2>&1 <<< '{"classification":"passed","phase":"completed","execution":{"exitCode":0},"rawLog":"all lifecycle markers present","structuredEvents":null}'; then
    printf 'PID lifecycle contract accepted raw markers without structured events\n' >&2
    return 1
  fi
  if jq '.structuredEvents[10].sequence=9' "$good_result" | jq -e "$pid_result_contract" >/dev/null; then
    printf 'PID lifecycle contract accepted out-of-order structured events\n' >&2
    return 1
  fi
  if jq '.structuredEvents[0].kind="RAW_LOG_MARKER"' "$good_result" | jq -e "$pid_result_contract" >/dev/null; then
    printf 'PID lifecycle contract accepted an untrusted event inventory\n' >&2
    return 1
  fi

  jq '
    .structuredEvents[9].payload.name="ProvenanceDiskFill" |
    .structuredEvents[13].payload.durationMillis=2000 |
    .structuredEvents[14].payload.name="ProvenanceDiskFill" |
    .structuredEvents[15].payload.durationMillis=2000
  ' "$good_result" > "$good_disk_result"
  printf 'fixture observed: %s\n' "$disk_fill_marker" > "$good_disk_log"
  validate_disk_fill_contract "$good_disk_result" "$good_disk_log"
  if jq '.classification="timed_out" | .phase="execution" | .failure={code:"job_timeout"} | .execution.exitCode=-1' "$good_disk_result" > "$test_root/wrong-disk-result.json" &&
    validate_disk_fill_contract "$test_root/wrong-disk-result.json" "$good_disk_log"; then
    printf 'disk-fill contract accepted the old timeout classification\n' >&2
    return 1
  fi
  printf 'fixture completed without saturation evidence\n' > "$test_root/missing-disk-marker.log"
  if validate_disk_fill_contract "$good_disk_result" "$test_root/missing-disk-marker.log"; then
    printf 'disk-fill contract accepted success without ENOSPC evidence\n' >&2
    return 1
  fi

  jq -n '{usage:{eventChannelMaximumBytes:4194304,eventChannelBufferedBytes:4096,eventChannelResourceBytes:0,eventChannelOverflowed:false,eventChannelRemoved:true}}' > "$test_root/good-event-channel.json"
  jq -e "$event_channel_usage_contract" "$test_root/good-event-channel.json" >/dev/null
  for mutation in \
    '.usage.eventChannelBufferedBytes=4194305' \
    '.usage.eventChannelResourceBytes=1' \
    '.usage.eventChannelOverflowed=true' \
    '.usage.eventChannelRemoved=false' \
    '.usage.eventChannelMaximumBytes=68719476736'; do
    if jq "$mutation" "$test_root/good-event-channel.json" | jq -e "$event_channel_usage_contract" >/dev/null; then
      printf 'event-channel usage contract accepted mutation: %s\n' "$mutation" >&2
      return 1
    fi
  done

  for sample in $(seq 0 49); do
    pids_current=45
    sandbox_pids=39
    pids_events=0
    if [[ "$sample" -ge 5 ]]; then
      pids_current=50
    fi
    [[ "$sample" -eq 5 ]] && sandbox_pids=48
    jq -cn \
      --argjson timestamp "$((sample * 50000000))" \
      --arg pidsCurrent "$pids_current" \
      --argjson pidsEvents "$pids_events" \
      --argjson sandboxPIDsCurrent "$sandbox_pids" \
      '{timestampNanoseconds:$timestamp,pidsMax:"65",pidsCurrent:$pidsCurrent,pidsEvents:("max "+($pidsEvents|tostring)+";"),memoryEvents:"low 0;high 0;max 0;oom 0;oom_kill 0;oom_group_kill 0;",sandboxPIDsCurrent:$sandboxPIDsCurrent}' \
      >> "$good_samples"
  done
  jq -es "$pid_resource_contract" "$good_samples" >/dev/null
  jq -es "$pid_saturation_contract" "$good_samples" >/dev/null
  if ! jq -c 'if .timestampNanoseconds==500000000 or .timestampNanoseconds==2450000000 then .sandboxPIDsCurrent=null else . end' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null; then
    printf 'PID resource contract rejected bounded unavailable guest observations\n' >&2
    return 1
  fi
  if ! jq -c 'if .timestampNanoseconds==500000000 or .timestampNanoseconds==2450000000 then .sandboxPIDsCurrent=null else . end' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null; then
    printf 'PID saturation contract rejected bounded unavailable guest observations\n' >&2
    return 1
  fi
  set +e
  jq -c '.sandboxPIDsCurrent=null' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null 2>&1
  rejection_status=$?
  set -e
  if [[ "$rejection_status" -ne 1 ]]; then
    printf 'PID resource contract did not cleanly reject all-null guest PID evidence (status=%s)\n' "$rejection_status" >&2
    return 1
  fi
  set +e
  jq -c '.sandboxPIDsCurrent=null' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null 2>&1
  rejection_status=$?
  set -e
  if [[ "$rejection_status" -ne 1 ]]; then
    printf 'PID saturation contract did not cleanly reject all-null guest PID evidence (status=%s)\n' "$rejection_status" >&2
    return 1
  fi
  set +e
  jq -c '.pidsEvents=""' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null 2>&1
  rejection_status=$?
  set -e
  if [[ "$rejection_status" -ne 1 ]]; then
    printf 'PID resource contract did not cleanly reject entirely unavailable denial evidence (status=%s)\n' "$rejection_status" >&2
    return 1
  fi
  if jq -c '.pidsCurrent="62"' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null; then
    printf 'PID resource contract accepted fewer than four outer reserve slots\n' >&2
    return 1
  fi
  if jq -c '.pidsMax="48"' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null; then
    printf 'PID resource contract accepted an outer limit without the runtime reserve\n' >&2
    return 1
  fi
  if jq -c '.pidsEvents="max 1;"' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null; then
    printf 'PID resource contract accepted an outer-controller denial\n' >&2
    return 1
  fi
  if jq -c 'if .sandboxPIDsCurrent==48 then .sandboxPIDsCurrent=47 else . end' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null; then
    printf 'PID saturation contract accepted a guest that did not reach its exact quota\n' >&2
    return 1
  fi
  for memory_failure in \
    'low 0;high 0;max 1;oom 0;oom_kill 0;oom_group_kill 0;' \
    'low 0;high 0;max 0;oom 1;oom_kill 0;oom_group_kill 0;' \
    'low 0;high 0;max 0;oom 0;oom_kill 1;oom_group_kill 0;'; do
    if jq -c --arg memoryEvents "$memory_failure" '.memoryEvents=$memoryEvents' "$good_samples" | jq -es "$pid_resource_contract" >/dev/null; then
      printf 'PID resource contract accepted a memory pressure event: %s\n' "$memory_failure" >&2
      return 1
    fi
  done
  if jq -c 'if .timestampNanoseconds>250000000 then .sandboxPIDsCurrent=48 else . end' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null; then
    printf 'PID saturation contract accepted missing guest release\n' >&2
    return 1
  fi
  if jq -c 'if .timestampNanoseconds>=1300000000 then .sandboxPIDsCurrent=48 else . end' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null; then
    printf 'PID saturation contract accepted a short guest release interval\n' >&2
    return 1
  fi
  if jq -c 'if .timestampNanoseconds>250000000 then .sandboxPIDsCurrent=2 else . end' "$good_samples" | jq -es "$pid_saturation_contract" >/dev/null; then
    printf 'PID saturation contract accepted teardown-only guest release\n' >&2
    return 1
  fi

  for repetition in 1 2 3; do
    jq -cn --argjson repetition "$repetition" '{fixture:"fork-pid-bomb",caseIdentity:("fork-pid-bomb-run-"+($repetition|tostring)),repetition:$repetition,accepted:true,cliExit:0,classification:"passed",phase:"completed",failureCode:null,completeLog:{state:"complete",truncated:false}}' >> "$good_summary"
  done
  jq -es "$pid_repetitions_contract" "$good_summary" >/dev/null
  if jq -c 'if .repetition==2 then .accepted=false else . end' "$good_summary" | jq -es "$pid_repetitions_contract" >/dev/null; then
    printf 'PID repetition contract accepted one failed repetition\n' >&2
    return 1
  fi

  [[ $(awk -F '\t' '$1=="fork-pid-bomb" && $2=="b4d936c12370892047839396786b6e65b1b5ccf65c6ddae70e283b43fe3e8e16" && $3==7593 {count++} END {print count+0}' "$fixture_manifest") -eq 1 ]]
  grep -Fq 'PLAN03_TOOLKIT_SHA: c4bf6bc9ddd0be3221e897e0ee9e2d409d206dec' "$repository_root/.github/workflows/plan03-acceptance.yml"
  [[ $(grep -Fc 'ref: c4bf6bc9ddd0be3221e897e0ee9e2d409d206dec' "$repository_root/.github/workflows/plan03-acceptance.yml") -eq 1 ]]
  [[ $(fixture_repetitions fork-pid-bomb) == 3 ]]
  [[ $(fixture_case_identity fork-pid-bomb 1) == fork-pid-bomb-run-1 ]]
  [[ $(fixture_case_identity fork-pid-bomb 2) == fork-pid-bomb-run-2 ]]
  [[ $(fixture_case_identity fork-pid-bomb 3) == fork-pid-bomb-run-3 ]]
  complete_cgroup_sample max current events cpu stat max current events
  if complete_cgroup_sample max current events cpu stat max "" events; then
    printf 'cgroup sample completeness accepted a missing controller field\n' >&2
    return 1
  fi
  if incomplete_cgroup_sample_is_teardown "$$"; then
    printf 'live runner was classified as teardown\n' >&2
    return 1
  fi
  (:) &
  local completed_pid=$!
  wait "$completed_pid"
  if ! incomplete_cgroup_sample_is_teardown "$completed_pid"; then
    printf 'completed runner was not classified as teardown\n' >&2
    return 1
  fi
  grep -Fq 'assert_no_residue "$case_identity" "$samples"' "$repository_root/scripts/plan03-acceptance.sh"
  grep -Fq 'write_pid_verification "$case_identity" "$repetition"' "$repository_root/scripts/plan03-acceptance.sh"
  printf 'Plan 03 PID acceptance contracts passed\n'
}

if [[ ${1:-} == --contract-test ]]; then
  [[ $# -eq 1 ]] || { printf 'unexpected contract-test arguments\n' >&2; exit 2; }
  run_contract_tests
  exit
elif [[ $# -ne 0 ]]; then
  printf 'Plan 03 acceptance takes no arguments\n' >&2
  exit 2
fi

required_environment=(
  PLAN03_ASSET_ROOT
  PLAN03_CGROUP_PARENT
  PLAN03_EVIDENCE_ROOT
  PLAN03_RUNNER
  PLAN03_RUNSC_BINARY
  PLAN03_TOOLKIT_SHA
  PLAN03_TOOLKIT_SOURCE_ROOT
  PLAN03_WORK_ROOT
  PROVENANCE_ROOTFS
  PROVENANCE_ROOTFS_IDENTITY
  PROVENANCE_RUNSC_PATH
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    printf '%s is required\n' "$name" >&2
    exit 2
  fi
done

for command_name in find git gzip jq sha256sum stat; do
  command -v "$command_name" >/dev/null || {
    printf '%s is required\n' "$command_name" >&2
    exit 2
  }
done

if [[ $(id -u) -ne 0 ]]; then
  printf 'Plan 03 acceptance must run as root in a disposable Linux environment\n' >&2
  exit 2
fi
if [[ -e "$PLAN03_EVIDENCE_ROOT" || -e "$PLAN03_WORK_ROOT" ]]; then
  printf 'PLAN03_EVIDENCE_ROOT and PLAN03_WORK_ROOT must not already exist\n' >&2
  exit 2
fi
if [[ ! "$PLAN03_CGROUP_PARENT" =~ ^/sys/fs/cgroup/provenance-plan03-acceptance-[A-Za-z0-9._-]+$ ]]; then
  printf 'refusing unexpected PLAN03_CGROUP_PARENT: %s\n' "$PLAN03_CGROUP_PARENT" >&2
  exit 2
fi
job_cgroup_root=${PLAN03_JOB_CGROUP_ROOT:-$PLAN03_CGROUP_PARENT/provenance}
if [[ "$job_cgroup_root" != "$PLAN03_CGROUP_PARENT/provenance" ]]; then
  printf 'refusing unexpected PLAN03_JOB_CGROUP_ROOT: %s\n' "$job_cgroup_root" >&2
  exit 2
fi
for path in "$PLAN03_ASSET_ROOT" "$PLAN03_TOOLKIT_SOURCE_ROOT" "$PROVENANCE_ROOTFS"; do
  [[ -d "$path" ]] || { printf '%s is not a directory\n' "$path" >&2; exit 2; }
done

pid_fixture_source="$PLAN03_TOOLKIT_SOURCE_ROOT/packages/test-fixtures/hostile/fork-pid-bomb/src/main/java/dev/provenance/fixtures/hostile/ForkPidBombPlugin.java"
[[ $(git -c safe.directory="$PLAN03_TOOLKIT_SOURCE_ROOT" -C "$PLAN03_TOOLKIT_SOURCE_ROOT" rev-parse HEAD) == "$PLAN03_TOOLKIT_SHA" ]] || {
  printf 'Plan 03 toolkit source checkout does not match %s\n' "$PLAN03_TOOLKIT_SHA" >&2
  exit 2
}
[[ -f "$pid_fixture_source" ]] || { printf 'missing pinned fork/PID fixture source\n' >&2; exit 2; }
pid_fixture_source_sha=$(sha256sum "$pid_fixture_source"); pid_fixture_source_sha=${pid_fixture_source_sha%% *}
[[ "$pid_fixture_source_sha" == 5c2ea8936a69f3d25e9b513a002e7df434d0839794721e637254a767a74649c8 ]] || {
  printf 'pinned fork/PID fixture source contract changed: %s\n' "$pid_fixture_source_sha" >&2
  exit 2
}
for path in "$PLAN03_RUNNER" "$PLAN03_RUNSC_BINARY" "$PROVENANCE_RUNSC_PATH"; do
  [[ -x "$path" ]] || { printf '%s is not executable\n' "$path" >&2; exit 2; }
done
[[ -d "$PLAN03_CGROUP_PARENT/runner" ]] || {
  printf '%s/runner must be a delegated cgroup directory\n' "$PLAN03_CGROUP_PARENT" >&2
  exit 2
}

mkdir -p \
  "$PLAN03_EVIDENCE_ROOT/jobs" \
  "$PLAN03_EVIDENCE_ROOT/results" \
  "$PLAN03_EVIDENCE_ROOT/resources" \
  "$PLAN03_WORK_ROOT/bundles" \
  "$PLAN03_WORK_ROOT/cache/content" \
  "$PLAN03_WORK_ROOT/state" \
  "$PLAN03_WORK_ROOT/workspaces"
chmod 0700 "$PLAN03_EVIDENCE_ROOT" "$PLAN03_WORK_ROOT"

secret=PROVENANCE_TEST_SECRET_03
# Raw workload console text is forgeable and cannot satisfy the trusted probe
# contract. Keep the retained lifecycle-failure shape as a mandatory negative.
if jq -e "$pid_result_contract" >/dev/null 2>&1 <<< '{"classification":"workload_failure","phase":"execution","failure":{"code":"gvisor_process_exit_nonzero"},"execution":{"exitCode":2},"structuredEvents":null}'; then
  printf 'fork PID result contract accepted an untrusted lifecycle failure\n' >&2
  exit 2
fi
paper_sha=8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e
java_sha=968c283e104059dae86ea1d670672a80170f27a39529d815843ec9c1f0fa2a03
probe_sha=abbccf45831ef998466542b19169731b9ec4f8a6c3525fce4d7a2c0b5f4b4b43
runtime_sha=ba1434cfc3af6fe145660e82f5b07ce9cb46cbc76d23c68a767a3717e7e5ca57

seed_cache() {
  local source=$1
  local expected_sha=$2
  local expected_size=$3
  [[ -f "$source" ]] || { printf 'missing acceptance asset: %s\n' "$source" >&2; exit 1; }
  local actual_sha actual_size
  actual_sha=$(sha256sum "$source")
  actual_sha=${actual_sha%% *}
  actual_size=$(stat -Lc %s "$source")
  if [[ "$actual_sha" != "$expected_sha" || "$actual_size" != "$expected_size" ]]; then
    printf 'acceptance asset mismatch: %s (sha=%s size=%s)\n' "$source" "$actual_sha" "$actual_size" >&2
    exit 1
  fi
  local destination="$PLAN03_WORK_ROOT/cache/content/sha256/${expected_sha:0:2}/${expected_sha:2}"
  mkdir -p "$(dirname -- "$destination")"
  install -m 0444 -- "$source" "$destination"
  printf '%s\t%s\t%s\n' "$actual_sha" "$actual_size" "$(basename -- "$source")" >> "$PLAN03_EVIDENCE_ROOT/assets.tsv"
}

seed_cache "$PLAN03_ASSET_ROOT/paper-1.21.8-60.jar" "$paper_sha" 52811717
seed_cache "$PLAN03_ASSET_ROOT/OpenJDK21U-jre_x64_linux_hotspot_21.0.8_9.tar.gz" "$java_sha" 51942501
seed_cache "$PLAN03_ASSET_ROOT/paper-probe-0.1.0.jar" "$probe_sha" 478837
seed_cache "$PLAN03_ASSET_ROOT/paper-prepared-runtime.tar.gz" "$runtime_sha" 153958528

generate_test_plan() {
  local fixture=$1
  local plugin=$2
  case "$fixture" in
    command-success)
      jq -cn --arg plugin "$plugin" '{targetPlugin:$plugin,stabilizationMilliseconds:2000,console:[{id:"command-success",command:"provenance-success",timeoutSeconds:10,assertions:[{stream:"combined",operator:"contains",pattern:"PROVENANCE_FIXTURE_COMMAND_OK",match:"present",minimumOccurrences:1},{stream:"combined",operator:"regex",pattern:"^PROVENANCE_.*_OK$",match:"present",minimumOccurrences:1}]}]}'
      ;;
    command-assertion-failure)
      jq -cn --arg plugin "$plugin" '{targetPlugin:$plugin,stabilizationMilliseconds:2000,console:[{id:"command-assertion-failure",command:"provenance-assertion-failure",timeoutSeconds:10,assertions:[{stream:"combined",operator:"contains",pattern:"PROVENANCE_FIXTURE_EXPECTED_OUTPUT",match:"present",minimumOccurrences:1}]}]}'
      ;;
    fork-pid-bomb)
      jq -cn --arg plugin "$plugin" '{targetPlugin:$plugin,stabilizationMilliseconds:30000}'
      ;;
    success|on-load-failure|on-enable-failure|missing-dependency)
      jq -cn --arg plugin "$plugin" '{targetPlugin:$plugin,stabilizationMilliseconds:2000,console:[]}'
      ;;
    *)
      jq -cn --arg plugin "$plugin" '{targetPlugin:$plugin,stabilizationMilliseconds:2000}'
      ;;
  esac
}

generate_job() {
  local fixture=$1 case_identity=$2 sha=$3 size=$4 plugin=$5 timeout=$6 output_limit=$7
  local test_plan memory_bytes=2147483648 pids=128
  if [[ "$fixture" == memory-bomb ]]; then
    memory_bytes=1610612736
  elif [[ "$fixture" == fork-pid-bomb ]]; then
    memory_bytes=4294967296
    pids=48
  fi
  test_plan=$(generate_test_plan "$fixture" "$plugin")
  jq -n \
    --arg fixture "$fixture" \
    --arg caseIdentity "$case_identity" \
    --arg sha "$sha" \
    --arg filename "$fixture-1.0.0.jar" \
    --arg plugin "$plugin" \
    --arg secret "$secret" \
    --argjson size "$size" \
    --argjson timeout "$timeout" \
    --argjson outputLimit "$output_limit" \
    --argjson memoryBytes "$memory_bytes" \
    --argjson pids "$pids" \
    --argjson testPlan "$test_plan" \
    '{schemaVersion:"provenance.local-job/v1alpha1",id:("plan03-"+$caseIdentity),provider:"paper",preparationTimeoutMilliseconds:120000,timeoutMilliseconds:$timeout,gracefulShutdownTimeoutMilliseconds:20000,maxOutputBytes:$outputLimit,environment:{artifactKind:"minecraft-plugin",environmentId:"paper-1.21.8-60-linux-amd64-temurin-21.0.8+9",target:{uri:("https://fixtures.example.com/"+$filename),sha256:$sha,filename:$filename,sizeBytes:$size},testPlan:$testPlan,memoryBytes:$memoryBytes,cpuMillis:1000,pids:$pids,diskBytes:1073741824,maxLineBytes:4096,redactSecrets:[$secret]}}'
}

fixture_selected() {
  local fixture=$1 selection=${PLAN03_FIXTURES:-}
  [[ -z "$selection" || ",$selection," == *",$fixture,"* ]]
}

while IFS=$'\t' read -r fixture sha size plugin timeout output_limit classification phase failure_code exit_code; do
  [[ -z "$fixture" || "$fixture" == \#* ]] && continue
  fixture_selected "$fixture" || continue
  source="$PLAN03_ASSET_ROOT/fixtures/$fixture-1.0.0.jar"
  seed_cache "$source" "$sha" "$size"
  repetitions=$(fixture_repetitions "$fixture")
  for repetition in $(seq 1 "$repetitions"); do
    case_identity=$(fixture_case_identity "$fixture" "$repetition")
    generate_job "$fixture" "$case_identity" "$sha" "$size" "$plugin" "$timeout" "$output_limit" > "$PLAN03_EVIDENCE_ROOT/jobs/$case_identity.json"
  done
done < "$fixture_manifest"

export PROVENANCE_PAPER_PROBE_URI=https://artifacts.example.com/paper-probe.jar
export PROVENANCE_PAPER_PROBE_SHA256=$probe_sha
export PROVENANCE_PAPER_PROBE_SIZE_BYTES=478837
export PROVENANCE_PAPER_PREPARED_RUNTIME_URI=https://artifacts.example.com/paper-prepared-runtime.tar.gz
export PROVENANCE_PAPER_PREPARED_RUNTIME_SHA256=$runtime_sha
export PROVENANCE_PAPER_PREPARED_RUNTIME_SIZE_BYTES=153958528
export PROVENANCE_PAPER_PREPARED_RUNTIME_MAX_EXPANDED_BYTES=163396442
export PROVENANCE_ARTIFACT_HOSTS=fixtures.example.com
export PROVENANCE_WORKSPACE_ROOT="$PLAN03_WORK_ROOT/workspaces"
export PROVENANCE_CACHE_ROOT="$PLAN03_WORK_ROOT/cache"
export PROVENANCE_GVISOR_STATE_ROOT="$PLAN03_WORK_ROOT/state"
export PROVENANCE_GVISOR_BUNDLE_ROOT="$PLAN03_WORK_ROOT/bundles"
export PROVENANCE_LOCAL_EXECUTE_ALLOW_HOSTILE_FIXTURES=true

sample_resources() {
  local fixture=$1 runner_pid=$2 destination=$3
  local leaf="" container_id="" memory_max memory_current memory_events cpu_max cpu_stat pids_max pids_current pids_events
  local sandbox_pids_current="" sandbox_cpu_usage="" sandbox_memory_usage="" sandbox_network_interfaces='[]' sample_number=0 stats_json
  while kill -0 "$runner_pid" 2>/dev/null; do
    leaf=$(find "$job_cgroup_root" -mindepth 1 -type d -name 'provenance-*' -print -quit 2>/dev/null || true)
    if [[ -n "$leaf" ]]; then
      container_id=$(basename -- "$leaf")
      memory_max=$(sed -n '1p' "$leaf/memory.max" 2>/dev/null || true)
      memory_current=$(sed -n '1p' "$leaf/memory.current" 2>/dev/null || true)
      memory_events=$(sed -n '1,$p' "$leaf/memory.events" 2>/dev/null | tr '\n' ';' || true)
      cpu_max=$(sed -n '1p' "$leaf/cpu.max" 2>/dev/null || true)
      cpu_stat=$(sed -n '1,$p' "$leaf/cpu.stat" 2>/dev/null | tr '\n' ';' || true)
      pids_max=$(sed -n '1p' "$leaf/pids.max" 2>/dev/null || true)
      pids_current=$(sed -n '1p' "$leaf/pids.current" 2>/dev/null || true)
      pids_events=$(sed -n '1,$p' "$leaf/pids.events" 2>/dev/null | tr '\n' ';' || true)
      if ! complete_cgroup_sample \
        "$memory_max" "$memory_current" "$memory_events" \
        "$cpu_max" "$cpu_stat" \
        "$pids_max" "$pids_current" "$pids_events"; then
        # The cgroup files may disappear between reads only after the runner
        # has exited. Skip that teardown observation; while the runner is
        # alive, fail loudly instead of silently weakening retained evidence.
        if incomplete_cgroup_sample_is_teardown "$runner_pid"; then
          break
        fi
        printf '%s observed an incomplete cgroup sample while runner pid %s was alive\n' "$fixture" "$runner_pid" >&2
        return 1
      fi
      if (( sample_number % 5 == 0 )); then
        # Never carry a successful runsc reading across a later failed stats
        # request. A null is truthful; a stale guest value can fabricate a
        # saturation or release interval after the sandbox has disappeared.
        sandbox_pids_current=""
        sandbox_cpu_usage=""
        sandbox_memory_usage=""
        sandbox_network_interfaces='[]'
        stats_json=$("$PROVENANCE_RUNSC_PATH" --root="$PROVENANCE_GVISOR_STATE_ROOT" events --stats "$container_id" 2>/dev/null || true)
        if jq -e '.type=="stats" and (.data.pids.current|type)=="number"' >/dev/null 2>&1 <<< "$stats_json"; then
          sandbox_pids_current=$(jq -r '.data.pids.current' <<< "$stats_json")
          sandbox_cpu_usage=$(jq -r '.data.cpu.usage.total // empty' <<< "$stats_json")
          sandbox_memory_usage=$(jq -r '.data.memory.usage.usage // empty' <<< "$stats_json")
          sandbox_network_interfaces=$(jq -c '.data.network_interfaces // []' <<< "$stats_json")
        fi
      fi
      jq -cn \
        --argjson timestamp "$(date +%s%N)" \
        --arg fixture "$fixture" \
        --arg cgroup "$leaf" \
        --arg containerId "$container_id" \
        --arg memoryMax "$memory_max" \
        --arg memoryCurrent "$memory_current" \
        --arg memoryEvents "$memory_events" \
        --arg cpuMax "$cpu_max" \
        --arg cpuStat "$cpu_stat" \
        --arg pidsMax "$pids_max" \
        --arg pidsCurrent "$pids_current" \
        --arg pidsEvents "$pids_events" \
        --arg sandboxPIDsCurrent "$sandbox_pids_current" \
        --arg sandboxCPUUsageNanoseconds "$sandbox_cpu_usage" \
        --arg sandboxMemoryUsageBytes "$sandbox_memory_usage" \
        --argjson sandboxNetworkInterfaces "$sandbox_network_interfaces" \
        '{timestampNanoseconds:$timestamp,fixture:$fixture,cgroup:$cgroup,containerId:$containerId,memoryMax:$memoryMax,memoryCurrent:$memoryCurrent,memoryEvents:$memoryEvents,cpuMax:$cpuMax,cpuStat:$cpuStat,pidsMax:$pidsMax,pidsCurrent:$pidsCurrent,pidsEvents:$pidsEvents,sandboxPIDsCurrent:(if $sandboxPIDsCurrent=="" then null else ($sandboxPIDsCurrent|tonumber) end),sandboxCPUUsageNanoseconds:(if $sandboxCPUUsageNanoseconds=="" then null else ($sandboxCPUUsageNanoseconds|tonumber) end),sandboxMemoryUsageBytes:(if $sandboxMemoryUsageBytes=="" then null else ($sandboxMemoryUsageBytes|tonumber) end),sandboxNetworkInterfaces:$sandboxNetworkInterfaces}' \
        >> "$destination"
    fi
    sample_number=$((sample_number + 1))
    sleep 0.05
  done
}

assert_no_residue() {
  local fixture=$1 samples=$2
  if find "$job_cgroup_root" -mindepth 1 -type d -name 'provenance-*' -print -quit 2>/dev/null | grep -q .; then
    printf '%s left a job cgroup\n' "$fixture" >&2
    return 1
  fi
  if find "$PLAN03_WORK_ROOT/bundles" -mindepth 1 -type d -print -quit | grep -q .; then
    printf '%s left a bundle\n' "$fixture" >&2
    return 1
  fi
  if find "$PLAN03_WORK_ROOT/state" -mindepth 1 -print -quit | grep -q .; then
    printf '%s left runsc state\n' "$fixture" >&2
    return 1
  fi
  if find "$PLAN03_WORK_ROOT/workspaces" -mindepth 1 -type d -print -quit | grep -q .; then
    printf '%s left a writable workspace\n' "$fixture" >&2
    return 1
  fi
  local container_id process_root command_line mount_info network_namespace
  while IFS= read -r container_id; do
    [[ -n "$container_id" ]] || continue
    for process_root in /proc/[0-9]*; do
      [[ -r "$process_root/cmdline" ]] || continue
      command_line=$(tr '\0' ' ' < "$process_root/cmdline" 2>/dev/null || true)
      mount_info=$(sed -n '1,$p' "$process_root/mountinfo" 2>/dev/null || true)
      if [[ "$command_line" == *"$container_id"* || "$mount_info" == *"$container_id"* ]]; then
        network_namespace=$(readlink "$process_root/ns/net" 2>/dev/null || true)
        printf '%s left process or mount residue at %s (net=%s)\n' "$fixture" "$process_root" "$network_namespace" >&2
        return 1
      fi
    done
  done < <(jq -r '.containerId' "$samples" 2>/dev/null | sort -u)
}

validate_result() {
  local fixture=$1 case_identity=$2 expected_classification=$3 expected_phase=$4 expected_code=$5 expected_exit=$6 timeout=$7 samples=$8
  local result="$PLAN03_EVIDENCE_ROOT/results/$case_identity.json"
  local complete_log="$PLAN03_EVIDENCE_ROOT/results/$case_identity.log.gz"
  local stderr_file="$PLAN03_EVIDENCE_ROOT/results/$case_identity.stderr"
  local decompressed="$PLAN03_WORK_ROOT/$case_identity.complete.log"
  local expected_memory=2147483648 expected_pids=128 expected_outer_pids=145
  if [[ "$fixture" == memory-bomb ]]; then
    expected_memory=1610612736
  elif [[ "$fixture" == fork-pid-bomb ]]; then
    expected_memory=4294967296
    expected_pids=48
    expected_outer_pids=65
  fi
  if [[ "$fixture" == fork-pid-bomb ]]; then
    jq -e "$pid_result_contract" "$result" >/dev/null
  fi
  jq -e \
    --arg fixture "$fixture" \
    --arg classification "$expected_classification" \
    --arg phase "$expected_phase" \
    --arg code "$expected_code" \
    --argjson exitCode "$expected_exit" \
    --argjson memoryBytes "$expected_memory" \
    --argjson pids "$expected_pids" \
    '(
      if $fixture=="fork-pid-bomb" then
        true
      else
        (.classification==$classification and .phase==$phase and ((.failure.code // "-")==$code) and (.execution.exitCode==$exitCode))
      end
    ) and .cleanup.succeeded==true and .usage.resourceClass.cpuMillis==1000 and .usage.resourceClass.memoryBytes==$memoryBytes and .usage.resourceClass.processCount==$pids and .usage.resourceClass.diskBytes==1073741824 and .usage.resourceClass.network=="none" and .usage.resourceClass.maximumConnections==0 and .usage.resourceClass.maximumBandwidthBytesPerSecond==0' \
    "$result" >/dev/null
  jq -e "$event_channel_usage_contract" "$result" >/dev/null
  gzip --test "$complete_log"
  local digest compressed_bytes uncompressed_bytes
  digest=$(sha256sum "$complete_log"); digest=${digest%% *}
  compressed_bytes=$(stat -c %s "$complete_log")
  gzip -cd "$complete_log" > "$decompressed"
  uncompressed_bytes=$(stat -c %s "$decompressed")
  jq -e \
    --arg digest "$digest" \
    --argjson compressed "$compressed_bytes" \
    --argjson uncompressed "$uncompressed_bytes" \
    '.completeLog.state=="complete" and .completeLog.truncated==false and .completeLog.sha256==$digest and .completeLog.compressedBytes==$compressed and .completeLog.uncompressedBytes==$uncompressed and .usage.compressedLogBytes==$compressed and .usage.completeLogBytes==$uncompressed and .usage.completeLogState=="complete" and (.usage.completeLogTruncated // false)==false' \
    "$result" >/dev/null
  for secret_target in "$result" "$stderr_file" "$decompressed"; do
    if grep -Fq "$secret" "$secret_target"; then
      printf '%s leaked the configured secret in %s\n' "$fixture" "$secret_target" >&2
      return 1
    fi
  done
  jq -e --arg memory "$expected_memory" --arg pids "$expected_outer_pids" 'select(.memoryMax==$memory and .cpuMax=="100000 100000" and .pidsMax==$pids)' "$samples" >/dev/null
  grep -Eq 'nr_throttled [1-9][0-9]*' "$samples"

  if [[ "$fixture" == enable-hang ]]; then
    jq -e --argjson timeout "$timeout" '.usage.wallTimeMilliseconds >= $timeout' "$result" >/dev/null
  fi
  case "$fixture" in
    enable-hang)
      grep -Fq 'Enabling ProvenanceEnableHang' "$decompressed"
      ;;
    memory-bomb)
      grep -Eq 'oom_kill [1-9][0-9]*' "$samples"
      grep -Fq 'Enabling ProvenanceMemoryBomb' "$decompressed"
      ;;
    fork-pid-bomb)
      jq -es "$pid_resource_contract" "$samples" >/dev/null
      jq -es "$pid_saturation_contract" "$samples" >/dev/null
      ;;
    disk-fill)
      validate_disk_fill_contract "$result" "$decompressed"
      ;;
    network-scan|metadata-endpoint)
      jq -e --arg plugin "$(jq -r '.environment.testPlan.targetPlugin' "$PLAN03_EVIDENCE_ROOT/jobs/$case_identity.json")" '.structuredEvents[] | select(.kind=="PLUGIN_STATE" and .payload.name==$plugin and .payload.enabled==true)' "$result" >/dev/null
      jq -es 'any(.[]; (.sandboxNetworkInterfaces|length)>0) and all(.[]; all(.sandboxNetworkInterfaces[]?; .Name=="lo"))' "$samples" >/dev/null
      ;;
    log-flood)
      # The fixture's achieved line rate varies with hosted-runner scheduling.
      # Require a sustained multi-live-window flood here; the deterministic
      # complete-log-boundary case independently proves exact retention above
      # 16 MiB by full size and SHA-256.
      jq -e '.usage.completeLogBytes >= (.usage.rawOutputBytes-100000) and .usage.completeLogBytes <= (.usage.rawOutputBytes+100000) and .usage.completeLogBytes > (.usage.capturedOutputBytes*4) and .usage.capturedOutputBytes==65536 and .usage.outputTruncated==true' "$result" >/dev/null
      [[ $(grep -Fc PROVENANCE_LOG_FLOOD "$decompressed") -ge 1000 ]]
      ;;
  esac
  rm -- "$decompressed"
}

write_pid_verification() {
  local case_identity=$1 repetition=$2 samples=$3 result=$4 destination=$5
  local runner_head
  runner_head=$(< "$PLAN03_EVIDENCE_ROOT/runner-head.txt")
  jq -n \
    --arg fixture fork-pid-bomb \
    --arg caseIdentity "$case_identity" \
    --argjson repetition "$repetition" \
    --arg toolkitSHA "$PLAN03_TOOLKIT_SHA" \
    --arg runnerHeadSHA "$runner_head" \
    --slurpfile samples "$samples" \
    --slurpfile result "$result" \
    '
      def pid_denials_or_null:
        (.pidsEvents // "") as $events |
        if ($events | test("^max [0-9]+;$")) then
          ($events | capture("^max (?<count>[0-9]+);$").count | tonumber)
        else
          null
        end;
      def sandbox_pids_or_null:
        if (.sandboxPIDsCurrent | type)=="number" then .sandboxPIDsCurrent else null end;
      def memory_event($name): (.memoryEvents | capture("(^|;)"+$name+" (?<count>[0-9]+);").count | tonumber);
      def guest_release_runs($peak):
        reduce .[] as $sample
          ({runs:[],current:[]};
           ($sample | sandbox_pids_or_null) as $guest_pids |
           if ($guest_pids==null) then
             .
           elif ($guest_pids > 2 and $guest_pids < $peak) then
             .current += [$sample]
           elif (.current | length) > 0 then
             .runs += [.current] | .current = []
           else
             .
           end) |
        if (.current | length) > 0 then .runs + [.current] else .runs end;
      def sequence($kind): first($result[0].structuredEvents[] | select(.kind==$kind) | .sequence);
      [$samples[] | sandbox_pids_or_null | select(. != null)] as $guestObservations |
      ($guestObservations | max) as $guestPeak |
      ([range(0; $samples | length) |
        select(($samples[.] | sandbox_pids_or_null)==$guestPeak)] | first) as $guestPeakIndex |
      ($samples[$guestPeakIndex+1:] | guest_release_runs($guestPeak)) as $guestReleaseRuns |
      ([$guestReleaseRuns[] |
        select((length >= 20) and
               ((.[-1].timestampNanoseconds - .[0].timestampNanoseconds) >= 1000000000))] | first) as $guestRelease |
      ([$samples[].pidsCurrent | tonumber] | max) as $outerPeak |
      ([$samples[] | pid_denials_or_null] | max) as $outerDenials |
      ($result[0].usage.resourceClass.processCount) as $requestedGuestMaximum |
      ($samples[0].pidsMax | tonumber) as $configuredOuterMaximum |
      {
        fixture:$fixture,
        caseIdentity:$caseIdentity,
        repetition:$repetition,
        toolkitSourceSHA:$toolkitSHA,
        runnerHeadSHA:$runnerHeadSHA,
        accepted:true,
        pids:{requestedGuestMaximum:$requestedGuestMaximum,configuredOuterMaximum:$configuredOuterMaximum,configuredRuntimeReserve:($configuredOuterMaximum-$requestedGuestMaximum),requiredOuterHeadroom:4,observedOuterMaximum:$outerPeak,minimumObservedOuterHeadroom:($configuredOuterMaximum-$outerPeak),observedGuestMaximum:$guestPeak,outerControllerMaxEvents:$outerDenials,unavailableOuterDenialSamples:([$samples[]|select(pid_denials_or_null==null)]|length),unavailableGuestPIDSamples:([$samples[]|select(sandbox_pids_or_null==null)]|length),guestNeverAboveRequestedMaximum:(all($guestObservations[]; .<=$requestedGuestMaximum)),outerNeverConsumesRequiredHeadroom:(all($samples[]; (.pidsCurrent|tonumber)<=($configuredOuterMaximum-4))),outerControllerDeniedNoProcesses:($outerDenials==0),guestQuotaReached:($guestPeak==$requestedGuestMaximum),guestPressureProof:{pinnedFixtureSHA256:"b4d936c12370892047839396786b6e65b1b5ccf65c6ddae70e283b43fe3e8e16",pinnedToolkitSourceSHA:$toolkitSHA,exactGuestQuotaObserved:($guestPeak==$requestedGuestMaximum),outerControllerDeniedNoProcesses:($outerDenials==0),paperLifecycleCompleted:($result[0].classification=="passed" and $result[0].execution.exitCode==0)},guestPeakTimestampNanoseconds:$samples[$guestPeakIndex].timestampNanoseconds,guestReleaseSamples:($guestRelease|length),sustainedGuestReleaseNanoseconds:($guestRelease[-1].timestampNanoseconds-$guestRelease[0].timestampNanoseconds),guestReleaseMinimum:([$guestRelease[].sandboxPIDsCurrent]|min),guestReleaseMaximum:([$guestRelease[].sandboxPIDsCurrent]|max),guestReleaseAboveTeardownFloor:(all($guestRelease[]; .sandboxPIDsCurrent>2)),guestReleaseBelowGuestPeak:(all($guestRelease[]; .sandboxPIDsCurrent<$guestPeak))},
        memory:{maxEvents:([$samples[]|memory_event("max")]|max),oomEvents:([$samples[]|memory_event("oom")]|max),oomKillEvents:([$samples[]|memory_event("oom_kill")]|max),noMemoryPressureEvents:(all($samples[]; memory_event("max")==0 and memory_event("oom")==0 and memory_event("oom_kill")==0))},
        completeLog:{state:$result[0].completeLog.state,truncated:$result[0].completeLog.truncated,sha256:$result[0].completeLog.sha256,compressedBytes:$result[0].completeLog.compressedBytes,uncompressedBytes:$result[0].completeLog.uncompressedBytes},
        lifecycle:{eventCount:($result[0].structuredEvents|length),ordered:true,continuousSequence:([$result[0].structuredEvents[].sequence]==[range(1;22)]),trustedInventory:([$result[0].structuredEvents[].kind]==["METADATA_INSPECTION","METADATA_INSPECTION","TEST_PLAN","PLUGIN_STATE","PLUGIN_STATE","PROBE_LOADED","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","PLUGIN_STATE","SERVER_LOADED","PLUGIN_STATE","PLUGIN_STATE","STABILIZATION_STARTED","TARGET_REQUIREMENT","STABILIZATION_COMPLETED","SERVER_READY","CLEAN_SHUTDOWN_REQUESTED","PLUGIN_STATE","PLUGIN_STATE","SERVER_STOPPED"]),targetEnabledSequence:first($result[0].structuredEvents[]|select(.kind=="PLUGIN_STATE" and .payload.name=="ProvenanceForkPidBomb" and .payload.loaded==true and .payload.enabled==true)|.sequence),serverLoadedSequence:sequence("SERVER_LOADED"),stabilizationStartedSequence:sequence("STABILIZATION_STARTED"),stabilizationCompletedSequence:sequence("STABILIZATION_COMPLETED"),serverReadySequence:sequence("SERVER_READY"),shutdownRequestedSequence:sequence("CLEAN_SHUTDOWN_REQUESTED"),serverStoppedSequence:sequence("SERVER_STOPPED")},
        cleanup:{reportedSucceeded:$result[0].cleanup.succeeded,residueAbsent:true,jobCgroupAbsent:true,bundleDirectoryAbsent:true,runscStateAbsent:true,writableWorkspaceDirectoryAbsent:true,processAndMountResidueAbsent:true}
      }
    ' > "$destination"
}

run_complete_log_boundary() {
  local output_bytes=$((20 * 1024 * 1024))
  local line=0123456789abcdef0123456789abcde
  local job="$PLAN03_EVIDENCE_ROOT/jobs/complete-log-boundary.json"
  local result="$PLAN03_EVIDENCE_ROOT/results/complete-log-boundary.json"
  local stderr_file="$PLAN03_EVIDENCE_ROOT/results/complete-log-boundary.stderr"
  local complete_log="$PLAN03_EVIDENCE_ROOT/results/complete-log-boundary.log.gz"
  local expected="$PLAN03_WORK_ROOT/complete-log-boundary.expected"
  local actual="$PLAN03_WORK_ROOT/complete-log-boundary.actual"
  local verification="$PLAN03_EVIDENCE_ROOT/results/complete-log-boundary-verification.json"

  jq -n \
    --arg script "yes '$line' | head -c $output_bytes" \
    '{schemaVersion:"provenance.local-job/v1alpha1",id:"plan03-complete-log-boundary",provider:"development-process",timeoutMilliseconds:120000,maxOutputBytes:65536,environment:{acknowledgeUnsandboxed:true,command:"/bin/sh",arguments:["-c",$script],maxLineBytes:64}}' \
    > "$job"

  bash -c 'kill -STOP $$; exec "$@"' bash \
    "$PLAN03_RUNNER" execute "$job" --complete-log "$complete_log" \
    > "$result" 2> "$stderr_file" &
  local runner_pid=$!
  local state=""
  for _ in {1..100}; do
    state=$(awk '/^State:/{print $2}' "/proc/$runner_pid/status" 2>/dev/null || true)
    [[ "$state" == T ]] && break
    sleep 0.01
  done
  [[ "$state" == T ]] || { printf 'complete-log boundary did not reach the launch gate\n' >&2; return 1; }
  printf '%s\n' "$runner_pid" > "$PLAN03_CGROUP_PARENT/runner/cgroup.procs"
  kill -CONT "$runner_pid"
  wait "$runner_pid"

  gzip --test "$complete_log"
  {
    printf '[stdout]\n'
    (set +o pipefail; yes "$line" 2>/dev/null | head -c "$output_bytes")
  } > "$expected"
  gzip -cd "$complete_log" > "$actual"

  local expected_size actual_size expected_sha actual_sha compressed_size compressed_sha
  expected_size=$(stat -c %s "$expected")
  actual_size=$(stat -c %s "$actual")
  expected_sha=$(sha256sum "$expected"); expected_sha=${expected_sha%% *}
  actual_sha=$(sha256sum "$actual"); actual_sha=${actual_sha%% *}
  compressed_size=$(stat -c %s "$complete_log")
  compressed_sha=$(sha256sum "$complete_log"); compressed_sha=${compressed_sha%% *}
  [[ "$expected_size" -gt $((16 * 1024 * 1024)) && "$actual_size" -eq "$expected_size" && "$actual_sha" == "$expected_sha" ]]
  jq -e \
    --arg sha "$compressed_sha" \
    --argjson compressed "$compressed_size" \
    --argjson uncompressed "$actual_size" \
    '.classification=="passed" and .completeLog.state=="complete" and .completeLog.truncated==false and .completeLog.sha256==$sha and .completeLog.compressedBytes==$compressed and .completeLog.uncompressedBytes==$uncompressed and .usage.completeLogState=="complete" and (.usage.completeLogTruncated // false)==false and .usage.capturedOutputBytes==65536 and .usage.outputTruncated==true' \
    "$result" >/dev/null
  jq -n \
    --argjson sourceBytes "$output_bytes" \
    --argjson uncompressedBytes "$actual_size" \
    --arg uncompressedSHA256 "$actual_sha" \
    --argjson compressedBytes "$compressed_size" \
    --arg compressedSHA256 "$compressed_sha" \
    '{formerBoundaryBytes:16777216,sourceBytes:$sourceBytes,uncompressedBytes:$uncompressedBytes,uncompressedSHA256:$uncompressedSHA256,compressedBytes:$compressedBytes,compressedSHA256:$compressedSHA256,entireArtifactVerified:true}' \
    > "$verification"
  rm -- "$expected" "$actual"
  printf 'accepted complete-log-boundary (%s bytes, sha256 %s)\n' "$actual_size" "$actual_sha"
}

run_paper_restart_recovery() {
  local directory="$PLAN03_EVIDENCE_ROOT/restart-recovery"
  local abandoned_job="$PLAN03_EVIDENCE_ROOT/jobs/restart-abandoned-paper.json"
  local recovery_result="$directory/recovery-result.json"
  local recovery_stderr="$directory/recovery.stderr"
  local recovery_log="$directory/recovery.log.gz"
  local abandoned_stdout="$directory/abandoned-result.partial.json"
  local abandoned_stderr="$directory/abandoned.stderr"
  local secret_file_name=restart-secret-bearing-input.txt
  mkdir -p "$directory"
  jq '.id="plan03-restart-abandoned-paper" | .timeoutMilliseconds=300000' \
    "$PLAN03_EVIDENCE_ROOT/jobs/enable-hang.json" > "$abandoned_job"

  bash -c 'kill -STOP $$; exec "$@"' bash \
    "$PLAN03_RUNNER" execute "$abandoned_job" --complete-log "$directory/abandoned.log.gz" \
    > "$abandoned_stdout" 2> "$abandoned_stderr" &
  local runner_pid=$!
  local state=""
  for _ in {1..100}; do
    state=$(awk '/^State:/{print $2}' "/proc/$runner_pid/status" 2>/dev/null || true)
    [[ "$state" == T ]] && break
    sleep 0.01
  done
  [[ "$state" == T ]] || { printf 'restart abandonment did not reach the launch gate\n' >&2; return 1; }
  printf '%s\n' "$runner_pid" > "$PLAN03_CGROUP_PARENT/runner/cgroup.procs"
  kill -CONT "$runner_pid"

  local bundle="" workspace="" container_id=""
  for _ in {1..1200}; do
    bundle=$(find "$PLAN03_WORK_ROOT/bundles" -mindepth 2 -maxdepth 2 -type f -name .provenance-run-attempted -printf '%h\n' -quit 2>/dev/null || true)
    workspace=$(find "$PLAN03_WORK_ROOT/workspaces" -mindepth 2 -maxdepth 2 -type f -name .provenance-workspace.json -exec sh -c 'jq -e '\''.jobId=="plan03-restart-abandoned-paper"'\'' "$1" >/dev/null && dirname -- "$1"' sh {} \; | head -n 1)
    if [[ -n "$bundle" && -n "$workspace" ]]; then
      container_id=$(jq -r '.containerId' "$bundle/.provenance-gvisor.json")
      if "$PROVENANCE_RUNSC_PATH" --root="$PROVENANCE_GVISOR_STATE_ROOT" state "$container_id" > "$directory/pre-crash-runsc-state.json" 2>/dev/null; then
        break
      fi
    fi
    sleep 0.1
  done
  [[ -n "$bundle" && -n "$workspace" && -n "$container_id" ]] || { printf 'actual Paper workspace did not become abandonable\n' >&2; return 1; }
  [[ -d "$job_cgroup_root/$container_id" ]]
  printf '%s\n' "$secret" > "$workspace/server/$secret_file_name"
  printf 'writable restart residue\n' > "$workspace/server/restart-writable.txt"
  find "$workspace" -xdev -printf '%M\t%u\t%g\t%p\n' | sort > "$directory/pre-crash-workspace.tsv"
  find "$bundle" -xdev -printf '%M\t%u\t%g\t%p\n' | sort > "$directory/pre-crash-bundle.tsv"
  jq -n \
    --argjson runnerPID "$runner_pid" \
    --arg bundle "$bundle" \
    --arg workspace "$workspace" \
    --arg containerId "$container_id" \
    --arg cgroup "$job_cgroup_root/$container_id" \
    --arg secretBearingInput "$workspace/server/$secret_file_name" \
    '{runnerPID:$runnerPID,bundle:$bundle,workspace:$workspace,containerId:$containerId,cgroup:$cgroup,secretBearingInput:$secretBearingInput}' \
    > "$directory/abandoned-identities.json"

  kill -KILL "$runner_pid"
  set +e
  wait "$runner_pid"
  local abandoned_status=$?
  set -e
  [[ "$abandoned_status" -eq 137 ]]
  "$PROVENANCE_RUNSC_PATH" --root="$PROVENANCE_GVISOR_STATE_ROOT" state "$container_id" > "$directory/post-crash-runsc-state.json"
  [[ -d "$bundle" && -d "$workspace" && -f "$workspace/server/$secret_file_name" ]]

  bash -c 'kill -STOP $$; exec "$@"' bash \
    "$PLAN03_RUNNER" execute "$PLAN03_EVIDENCE_ROOT/jobs/success.json" --complete-log "$recovery_log" \
    > "$recovery_result" 2> "$recovery_stderr" &
  local recovery_pid=$!
  state=""
  for _ in {1..100}; do
    state=$(awk '/^State:/{print $2}' "/proc/$recovery_pid/status" 2>/dev/null || true)
    [[ "$state" == T ]] && break
    sleep 0.01
  done
  [[ "$state" == T ]] || { printf 'restart recovery did not reach the launch gate\n' >&2; return 1; }
  printf '%s\n' "$recovery_pid" > "$PLAN03_CGROUP_PARENT/runner/cgroup.procs"
  kill -CONT "$recovery_pid"
  wait "$recovery_pid"
  jq -e '.classification=="passed" and .cleanup.succeeded==true and .completeLog.state=="complete"' "$recovery_result" >/dev/null
  gzip --test "$recovery_log"

  [[ ! -e "$bundle" && ! -e "$workspace" && ! -e "$job_cgroup_root/$container_id" ]]
  if find "$PLAN03_WORK_ROOT/state" -xdev -print | grep -Fq "$container_id"; then
    printf 'restart left runsc state for %s\n' "$container_id" >&2
    return 1
  fi
  if grep -R -F -l -- "$secret" "$PLAN03_WORK_ROOT/bundles" "$PLAN03_WORK_ROOT/state" "$PLAN03_WORK_ROOT/workspaces" > "$directory/post-restart-secret-hits.txt"; then
    printf 'restart left secret-bearing inputs\n' >&2
    return 1
  fi
  printf '{"containerId":"%s"}\n' "$container_id" > "$directory/abandoned-container.ndjson"
  assert_no_residue restart-recovery "$directory/abandoned-container.ndjson"
  {
    find "$PLAN03_WORK_ROOT/bundles" -mindepth 1 -print
    find "$PLAN03_WORK_ROOT/state" -mindepth 1 -print
    find "$PLAN03_WORK_ROOT/workspaces" -mindepth 1 -print
    find "$job_cgroup_root" -mindepth 1 -print 2>/dev/null || true
  } > "$directory/post-restart-residue.txt"
  jq -n --arg containerId "$container_id" '{paperWorkspacePrepared:true,runnerKilled:true,productionStartupReconciliation:true,containerId:$containerId,containerRemoved:true,runscStateRemoved:true,cgroupRemoved:true,processesRemoved:true,workspaceRemoved:true,writableFilesRemoved:true,secretBearingInputsRemoved:true}' > "$directory/verdict.json"
  printf 'accepted real Paper restart recovery (%s)\n' "$container_id"
}

printf '%s\n' "$(git -c safe.directory="$repository_root" -C "$repository_root" rev-parse HEAD)" > "$PLAN03_EVIDENCE_ROOT/runner-head.txt"
printf '%s\n' "$PLAN03_TOOLKIT_SHA" > "$PLAN03_EVIDENCE_ROOT/toolkit-source-head.txt"
cp "$fixture_manifest" "$PLAN03_EVIDENCE_ROOT/fixtures.tsv"
{
  uname -a
  printf 'cgroup-v2=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
  "$PROVENANCE_RUNSC_PATH" --version
  sha256sum "$PLAN03_RUNNER" "$PLAN03_RUNSC_BINARY" "$PROVENANCE_RUNSC_PATH"
  printf '%s  %s\n' "$pid_fixture_source_sha" "$pid_fixture_source"
} > "$PLAN03_EVIDENCE_ROOT/identities.txt" 2>&1

run_complete_log_boundary
run_paper_restart_recovery

while IFS=$'\t' read -r fixture sha size plugin timeout output_limit classification phase failure_code exit_code; do
  [[ -z "$fixture" || "$fixture" == \#* ]] && continue
  fixture_selected "$fixture" || continue
  repetitions=$(fixture_repetitions "$fixture")
  for repetition in $(seq 1 "$repetitions"); do
    case_identity=$(fixture_case_identity "$fixture" "$repetition")
    result="$PLAN03_EVIDENCE_ROOT/results/$case_identity.json"
    stderr_file="$PLAN03_EVIDENCE_ROOT/results/$case_identity.stderr"
    complete_log="$PLAN03_EVIDENCE_ROOT/results/$case_identity.log.gz"
    samples="$PLAN03_EVIDENCE_ROOT/resources/$case_identity.ndjson"
    : > "$samples"

    bash -c 'kill -STOP $$; exec "$@"' bash \
      "$PLAN03_RUNNER" execute "$PLAN03_EVIDENCE_ROOT/jobs/$case_identity.json" --complete-log "$complete_log" \
      > "$result" 2> "$stderr_file" &
    runner_pid=$!
    state=""
    for _ in {1..100}; do
      state=$(awk '/^State:/{print $2}' "/proc/$runner_pid/status" 2>/dev/null || true)
      [[ "$state" == T ]] && break
      sleep 0.01
    done
    [[ "$state" == T ]] || { printf '%s did not reach the launch gate\n' "$case_identity" >&2; exit 1; }
    printf '%s\n' "$runner_pid" > "$PLAN03_CGROUP_PARENT/runner/cgroup.procs"
    kill -CONT "$runner_pid"
    sample_resources "$case_identity" "$runner_pid" "$samples" &
    monitor_pid=$!
    set +e
    wait "$runner_pid"
    status=$?
    set -e
    wait "$monitor_pid"

    expected_status=1
    [[ "$classification" == passed ]] && expected_status=0
    if [[ "$status" -ne "$expected_status" ]]; then
      printf '%s exit status=%s, want %s\n' "$case_identity" "$status" "$expected_status" >&2
      exit 1
    fi
    [[ -s "$samples" ]] || { printf '%s produced no cgroup samples\n' "$case_identity" >&2; exit 1; }
    validate_result "$fixture" "$case_identity" "$classification" "$phase" "$failure_code" "$exit_code" "$timeout" "$samples"
    assert_no_residue "$case_identity" "$samples"
    if [[ "$fixture" == fork-pid-bomb ]]; then
      verification="$PLAN03_EVIDENCE_ROOT/results/$case_identity-verification.json"
      write_pid_verification "$case_identity" "$repetition" "$samples" "$result" "$verification"
    fi
    jq -cn \
      --arg fixture "$fixture" \
      --arg caseIdentity "$case_identity" \
      --argjson repetition "$repetition" \
      --argjson cliExit "$status" \
      --slurpfile result "$result" \
      '{fixture:$fixture,caseIdentity:$caseIdentity,repetition:$repetition,accepted:true,cliExit:$cliExit,classification:$result[0].classification,phase:$result[0].phase,failureCode:($result[0].failure.code // null),wallTimeMilliseconds:$result[0].usage.wallTimeMilliseconds,usage:$result[0].usage,completeLog:$result[0].completeLog}' \
      >> "$PLAN03_EVIDENCE_ROOT/summary.ndjson"
    printf 'accepted %s\n' "$case_identity"
  done
done < "$fixture_manifest"

jq -es "$pid_repetitions_contract" "$PLAN03_EVIDENCE_ROOT/summary.ndjson" >/dev/null

(
  cd "$PLAN03_EVIDENCE_ROOT"
  find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > "$PLAN03_WORK_ROOT/manifest.sha256"
  mv "$PLAN03_WORK_ROOT/manifest.sha256" manifest.sha256
  sha256sum --check --strict manifest.sha256
)
printf 'Plan 03 acceptance bundle: %s\n' "$PLAN03_EVIDENCE_ROOT"
