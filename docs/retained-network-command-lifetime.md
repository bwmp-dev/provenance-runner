# Retained network command lifetime

Protected namespace commands carry a kernel parent-death SIGKILL in addition to
their existing three-second context deadline and bounded output. The creating
Go OS thread stays locked through command completion, because Linux binds that
signal to the creating thread rather than the whole parent process. The no-fork
nsenter invocation preserves the exact child identity across tool execution.

Set-ID executables were already refused. File-capability metadata is now also
refused, because privileged execution can clear the parent-death signal. Tool
content hashes do not cover that metadata; it is checked separately on each
retained descriptor. Unsupported capability attributes are accepted only when
the filesystem reports that it does not support them.

The disposable namespace suite requires three controller-crash cases. A real
retained command proves its installed death signal, the fixture captures its
pidfd and kills its controller, then verifies SIGKILL and reaps the command
within one second—less than the normal command timeout. The fixture temporarily
acts as a subreaper and restores its prior state. Capability-bearing copies of
an otherwise valid tool are refused without executing them.

This closes one source of surviving namespace references after a controller
crash. It does not prove that all processes, links or namespace references are
gone, replace durable owner recovery, or release global capacity by itself.
