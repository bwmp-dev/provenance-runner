# Measured runtime CPU visibility

The root-owned job cgroup enforces CPU bandwidth independently of runsc. Since
the closed mapped launcher uses `--ignore-cgroups=true`, runsc does not derive
its CPU count from that cgroup. The pinned runsc source at `eeff98ba9777`
(`runsc/sandbox/sandbox.go` and `runsc/boot/loader.go`) otherwise falls back to
the CPUs visible to its process and sizes sentry parallelism from that count.

On the 32-thread fixture host, diagnostic-only executions observed the workload
leaf reaching `pids.peak=81`, matching `pids.max=81` (64 job tasks plus the
unchanged 17-task runtime reserve), with denied creations **before** cleanup
sets `pids.max=0`. Failed executions returned 2, 125 or 137, without an OOM
event. Post-cleanup parent counters alone were not sufficient evidence because
cleanup can itself cause a process-creation denial. These diagnostic branches
and their extra logging are not release artifacts.

The closed launcher now receives CPU millicores only from the authenticated
job's already validated effective policy. It accepts canonical integers from
10 through 64000, not arbitrary CPU lists or runtime flags. After the existing
authority gate, the child stays OS-thread-locked while selecting a subset of
its inherited affinity, applying and reading back that mask, and execing the
retained runsc descriptor. Selection uses the quota-rounded CPU count with a
floor of two when available, matching runsc's own quota-count convention.

The independently enforced CPU-time quota, memory limit, PID maximum, guest
allowance, preparation/execution deadlines and authority rules are unchanged.
This is a runtime-parallelism bound, not a claim that affinity grants authority
or that every possible job fits its requested process budget. The controller,
router and unrelated host services do not have their affinity changed.

Unit tests cover sparse inherited masks, rounding, invalid/noncanonical input,
single-CPU hosts, and no mask expansion. A subprocess exec test checks both
inherited kernel affinity and the new Go process's CPU visibility while proving
the parent's affinity is unchanged. Disposable stress and complete kernel,
gateway/Paper, exact-head CI and post-merge acceptance remain required before
production activation; unit tests alone do not complete this release gate.

Before closing process admission during cleanup, the root-owned leaf also
captures its own bounded `pids.events` scalar. The immutable observation is
available only after leaf retirement. A missing/invalid observation or a nonzero
denial count makes a completed measured execution an infrastructure failure,
even if runsc returned an ordinary exit code. Cleanup still proceeds if reading
the counter fails; the absence of evidence never becomes evidence of zero
denials. Denials introduced by cleanup or later stale-descriptor attempts do
not alter the captured value. A disposable kernel regression deliberately fills
a one-task leaf and checks actual `EAGAIN`, retirement, and the frozen counter.
