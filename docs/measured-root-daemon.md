# Measured root daemon

`provenance-runner measured-service /etc/provenance/measured-service.json` is a
separate Linux root command. It clears supplementary groups before loading root
provisioning, and never enters enrollment or gateway connection setup. It loads
no gateway, database, marketplace, or platform-management credentials.

The version-1 `DaemonConfig` contains public runtime verification material,
expected runner/runsc/root-image SHA-256 pins, literal DNS resolver endpoint,
protected tool paths and pins, worker UID/GID, separate workload/router mappings,
sensitive prefixes, input and DNS bounds, and a maximum effective policy encoded
as Protobuf JSON. Paths identify an already provisioned socket directory, empty
aggregate cgroup parent, persistent journal directories, bundle root, mounted
SquashFS, backing image and loop device. It does not mount storage, create the
cgroup parent, widen host routes, set global forwarding, reserve identities or
install quotas. Those remain operator provisioning prerequisites.

The configuration file must be a root-owned mode-0600 regular file with one
link, beneath root-owned non-writable parents. Loading rejects symlinks, FIFOs,
oversized or changing files, duplicate keys (including case variants), unknown
fields, invalid identities, reused paths, missing pins, invalid limits and
non-literal resolver endpoints. Parser errors do not include file contents.

Provisioning handles are retained. Actual measurements must match the configured
pins; public labels are not substituted for measured objects. Pinned acquisition
checks those pins before even invoking the sandbox executable for its version,
using a fixed environment. Controller startup then recovers owned cgroups,
bundles and uplinks before the listener is exposed. The
listener serializes requests with execution; there is no unbounded goroutine or
descriptor queue. Invalid jobs can be refused without poisoning an otherwise
retired controller. Listener or controller failure stops admission.

Shutdown closes admission and retires the controller before closing journals,
measurements and tool handles. Partial initialization returns its owner for the
same cleanup path. If cleanup fails, the command stops admitting work and stays
alive, retrying cleanup while retaining ownership. Cancellation is not treated
as proof of cleanup. It never recursively deletes supplied paths or unmounts the
operator's root image.

Disposable acceptance reopens the fixture's empty persistent journals through
`OpenDaemon`, loads a private root configuration, rejects permissive file modes,
symlinks, hardlinks and incorrect binary pins, then executes the full synthetic
job through `Daemon.Serve`. A subsequent authenticated idle probe must succeed,
and all daemon owners must close before journal and bundle checks pass. Three
repetitions are mandatory alongside the existing service and kernel suite. The
service-suite timeout increases to accommodate the added repetitions; individual
job deadlines and all resource limits are unchanged.

This is not a production deployment. Host identity exclusivity, durable storage
quotas, concrete provisioning/configuration, connected-worker integration,
measured secrets and real Java/Paper compatibility still require acceptance.
