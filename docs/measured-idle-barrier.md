# Root idle barrier

After stopping and joining a failed local session, a worker can open a fresh
authenticated root channel and call `measuredclient.CheckIdle`. A random 32-byte
challenge and matching root reply are bounded by one five-second deadline and
the caller's cancellation. Wrong phases, changed challenges, attached files,
socket EOF, and non-root peers fail closed. Both sides close the probe channel;
it cannot carry a subsequent execution request.

The root service serializes this probe with execution admission. A previous
session must finish deferred cleanup before the service lock becomes available.
An active, failed, stopped, unprovisioned, or resource-drifted controller cannot
reply successfully. Its active slot is cleared only after owned objects and
journals retire. Root also revalidates the measured helper before replying.

This is a momentary capacity barrier, not a job result or a public execution
receipt. It does not claim that a failed job ran, validate guest output, reserve
future admission, or renew authority. The connected worker must serialize its
own admission and retain capacity if the probe fails; a later attempt still
requires fresh job authorization and full root admission.

Disposable acceptance requires authenticated probes after normal completion,
authority withdrawal, pre-release refusal, and event refusal, three times each.
It separately rejects root responses with a wrong challenge, wrong phase, wrong
length, attached descriptor, or bare EOF. The existing busy-controller fixture
also requires idle refusal while a real session remains owned. Input-assembly
tests ensure an idle probe cannot become a Start request and malformed probes
close every received descriptor.

The daemon listener loop and connected-worker retry/capacity integration remain
separate work. Production network-policy v2 remains disabled.
