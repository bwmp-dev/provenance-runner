# Explicit no-network v2 admission

`AdaptNoNetworkV2` validates the complete original v2 configuration, policy and
hashes, and requires the exclusive `networkV2.mode=none` policy. It then derives
the existing bounded local Paper request without modifying the wire job or
replacing its policy. Terminal evidence continues to bind the original v2 job.
The legacy `AdaptJob` method still refuses all network-v2 specifications.

With `PROVENANCE_MEASURED_NONE_PROVIDER=isolated`, the measured worker also opens
the independently provisioned existing no-network gVisor provider. All ordinary
no-network workspace, sandbox, root-image and state settings remain mandatory;
its reconciliation and instance locks must succeed before worker startup. The
root network service has its own separately owned journals and endpoint.

Only an explicitly admitted v2 none job selects the no-network provider. An
enabled-network execution failure never falls back to it. Both routes share the
connected worker's one-session admission lock. Failed cleanup on either route
stops capacity on both. v1 input cannot enter this new dispatch path.

No current network grant is fabricated for `none`: the existing gVisor
no-network isolation remains the execution boundary. This is not routed root
execution and must not be represented as an enabled-network measurement.
Production configuration, protocol advertisement and actual composed no-network
acceptance remain separate gates; unit dispatch/admission tests alone do not
complete them.
