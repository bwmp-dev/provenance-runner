# Measured worker failure investigation

The post-main CI run `35138077789` for merge
`261fae5e730f8c99a36b404ba9bd7038888d7c2f` failed a composed worker execution
after guest startup. The fixture recorded infrastructure failure and successful
cleanup, with `ROOT_SERVICE_STARTED` but no completion marker. The earlier
PR run `35129602372` had a similar failure. Neither is treated as a waived check
or as a plugin incompatibility. No production capability rollout is accepted
from those observations.

The disposable service fixture now records the root's process exit,
infrastructure decision, controller wait error, relay/diagnostic errors and
cancellation cause. The hook is package-private, unset by constructors, and
unavailable through daemon configuration or the control protocol. It receives
no guest output, secret values or descriptors. Fixture-only cgroup memory and
process event counters help distinguish resource exhaustion from protocol or
authority failure. The hook is retained across the fixture's daemon reopen.

`measured_acceptance.py --worker-stress` requires twenty additional complete
worker executions before the existing three-repetition acceptance suite. The
stress subprocess has its own 220-second overall timeout; individual execution
budgets, quotas, authority deadlines, denial checks and cleanup requirements are
unchanged. The outer harness allows the additional test time, not additional
workload time. CI's existing 15-minute job ceiling remains unchanged.

The first local stress attempt completed nineteen executions and timed out on
the twentieth because its initial 150-second harness budget was too short. It
is a failed harness run, not a reproduction of the earlier early-session fault.
The corrected local stress stage completed all twenty executions. A separate
three-repetition diagnostic acceptance run passed, including owned loop and
journal retirement. These local passes do not establish the intermittent
failure's root cause; CI diagnostics and the remaining release gates still apply.
