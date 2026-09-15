# Observing the living sandbox's measured objects

`Lease.ValidateChildObjects` checks a living retained direct child, not a PID
supplied by a workload. It opens that child's current executable and the closed
`<job-id>/.measured-root` location through the retained procfs directory. The
fixed procfs executable/root links are intentional kernel-object references;
subsequent traversal beneath the retained process root rejects symlinks and
escapes. Namespace identity and pidfd liveness are checked around each capture.

The executable must be the exact protected sandbox inode retained by the lease.
The child's private root must be the exact retained SquashFS root inode and its
mount must remain read-only. The lease independently revalidates protected
executable/image hashes and the original read-only loop-image mapping. The live
objects are captured again after measurement to refuse replacement during the
observation. All temporary descriptors are closed; errors contain no host paths
or process contents.

This boundary does not authorize a route, prove resource enforcement, report
guest success, or produce a terminal runtime claim. In particular it does not
broaden `Snapshot.Valid` to accept requested network labels. Future network
evidence must combine this observation with the exact child resource proof,
current native route authority, and complete job/attempt/policy binding.

The disposable measured fixture rejects the gated runner before it executes the
sandbox. During live guest traffic it checks the real executable and mounted
root, and rejects the living router, a nil child, and an input-directory path.
This remains an internal root-controller boundary, not a public path/PID RPC.
