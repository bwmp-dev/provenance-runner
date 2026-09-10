# Versioned terminal evidence rollout

V2 adds explicit literal `contains` assertions to the existing bounded, private
terminal proof. It does not change the test predicates, historical v1 evidence,
or public claims. Complete coverage is not passing, signing or publication.

The default runner continues to advertise v1 only. After a v2-capable backend
consumer has been deployed and accepted, the operator can opt in at process start:

```sh
provenance-runner connect /path/to/connect.json --enable-terminal-evidence-v2
```

This is a process option, not a field in customer jobs or the connect JSON.
The runner advertises v2 only with a capable worker. It retains v1 advertisement
for old queued proofs. The selected version is saved with the accepted job;
reconnects do not upgrade or downgrade that selection.

Drain before changing this option. Removing it does not convert a pending v2
proof: delivery refuses until v2 admission returns, retaining the exact bytes.
Never remove a journal or strip its proof to force a downgrade. Old binaries may
reject a journal with the new field; retain a matching binary for recovery.

Current development has local contract, producer and database acceptance tests,
not a production v2 rollout. Toolkit release pin reconciliation, exact-head and
post-main CI, consumer-first deployment, and a real complete-literal pilot remain
required. Test fixture measurements are synthetic, not deployed measurements.
