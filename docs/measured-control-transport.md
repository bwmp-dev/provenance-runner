# Measured control-channel framing

`internal/controlchannel` owns an already connected Linux Unix seqpacket socket
after verifying its kernel peer UID against trusted local configuration. It
rejects stream sockets and unidentified or mismatched peers. Future worker clients
must require UID 0 and connect through a root-protected pathname; the root service
must require its separately provisioned non-root worker UID. No listener or root
execution endpoint is enabled by this package.

Every packet has a closed version/kind header, zero reserved fields, exact payload
and file counts, and an independent consecutive sequence starting at 1 in each
direction. Frames are limited to 64 KiB of payload and 16 file descriptors. Each
operation requires a future deadline no more than 30 seconds away. Any refusal,
timeout, truncation or I/O failure closes the connection permanently.

Only read-only regular file descriptors are accepted. Received descriptors are
atomically close-on-exec and belong to the successful recipient; every delivered
descriptor is closed on refusal, including ancillary truncation. Send duplicates
borrowed descriptors for the operation and closes those duplicates afterwards.
These are untrusted inputs: later staging must still check the permitted local
filesystem, role, exact job-bound size/digest and copied content. Read-only access
does not prove that another process cannot modify the backing inode.

Payload interpretation, current-authority validation, Paper input-role derivation,
job correlation, per-kind direction/state checks, sealed evidence generation,
global connection limits and protected socket provisioning are separate required
service integration. A valid frame is not permission to execute a command or
accept evidence. This transport does not carry platform-management credentials
and does not change the existing network-v2 production fence.

Local non-executing socketpair tests cover peer/type refusal, descriptor contents
and close-on-exec, exact framing, oversized payloads and ancillary rights,
writable descriptor refusal, descriptor-leak checks, deadlines and permanent
channel closure. These tests do not execute hostile artifacts or require root.
