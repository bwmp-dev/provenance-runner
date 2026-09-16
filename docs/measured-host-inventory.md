# Read-only measured host inventory

Run `python3 -B scripts/measured-host-inventory.py --workload-id 262144
--router-id 262145 --worker-uid 994 --storage-parent /var/lib/provenance-runner`
as root on the candidate host (as one command). It reads account/subordinate ID
allocations, process credentials, noninitial user-namespace mappings and storage
availability. It does not inspect process command lines or environments, reserve
identities, create storage, change services or authorize network activation.

Both UID and GID namespaces must be clear because each role uses the same numeric
UID/GID. Supplementary groups and account primary groups also count. A missing
passwd entry is insufficient: an ID may already belong to a subordinate range.
Malformed/inaccessible inventory fails without dumping its contents. Processes
that vanish during collection are counted rather than silently treated as proof
of a complete inventory. The result is only a point-in-time observation.

`readyForActivation` is always false. A host-wide filesystem ownership scan,
durable account/identity reservation, bounded persistent storage, trusted daemon
provisioning and the other live acceptance gates remain necessary. Free space is
not a disk quota. This diagnostic must never become an admission authorization.

## Observation, 2026-09-16

On the dedicated runner, 200000 was unsuitable even without a named account:
the existing Provenance subordinate allocation covers 165536 through 231071.
The subsequent read-only snapshot found no account, subordinate-range, running
credential or user-namespace mapping conflict for candidate IDs 262144/262145
(210 processes, no other user namespaces, no vanished processes). No IDs were
reserved. The existing worker remains UID 994 and continues running unchanged.
The writable ext4 root has no persistent quota configuration; its available
space does not resolve the measured storage activation gate.
