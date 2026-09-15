# Root listener and provider admission

The local service listener retains a provisioned root-owned directory with mode
0711 and exclusively creates `control.sock`, mode 0660, owned by root and the
configured worker group. Connections must also have the exact configured non-root
worker UID according to `SO_PEERCRED`. Clients independently require root as their
peer. Neither group membership nor a claimed UID in a payload grants authority.

The listener validates the retained directory and exact socket inode before and
after acceptance. Observed drift permanently stops admission; restoring mode does
not resume that listener. Close removes only its own socket inode. A pre-existing
entry is never replaced, and a foreign replacement is left untouched on cleanup
refusal. Partial constructors may return an owner with an error; retain it and
retry Close, never substitute broad directory removal. The service manager must
provide lifecycle cleanup for its dedicated runtime directory after a crash;
this listener does not guess that a pre-existing socket is stale.

The generic gVisor controller exposes only its existing trusted in-process
provisioning and ownership API. These types are not RPC schemas. Local paths,
identity maps, maximum policy, tools and journals come from provisioning; commands
and input identities must be derived by the provider-specific root admission
function. Returning a non-nil controller/job on failure retains cleanup ownership.

Paper request preparation performs canonical projected-job decoding, local signed
runtime validation and derivation of immutable input metadata and guest bootstrap.
It requires no HTTP client. Until the measured test-secret injection path is
composed, secret-bearing jobs are refused instead of silently losing declared
inputs. A prepared request is not execution authority: exact descriptor count,
bounded hash-verified copying, local limits and fresh reconciliation still apply.

Disposable tests run a real non-root local client that authenticates its root
peer. They verify wrong-UID rejection, pre-existing and replaced-entry refusal,
permanent mode-drift refusal and exact cleanup. The trusted test client is copied
into its own traversable directory; durable staging and journals remain private.
The ordinary suite covers unprovisioned admission and signed request derivation.

This change does not yet register a daemon command, dispatch jobs over the socket,
integrate the credentialed worker, inject test secrets or activate production.
Those remain mandatory before the new execution path may be advertised.
