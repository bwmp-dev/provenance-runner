# Job-bound measured Paper inputs

The Paper runtime source can derive an immutable input plan without making a
network request or executing anything. It verifies the existing signed runtime
manifest against locally configured origin/key authority and requires its exact
Paper build, server digest, Java version/distribution and Linux amd64 environment.
The complete network-v2 policy hash and job/lease/attempt identities must validate;
unknown Protobuf fields anywhere in the bounded job are refused.

Fixed roles are Java archive, Paper JAR, probe JAR, prepared-runtime archive,
target JAR, numbered dependency JARs and the derived probe-plan JSON. Runtime
digests/sizes come from the signed catalog. Target and dependency digests must
match their separate job-hash entries. Dependencies must match configured IDs,
have distinct plugin names and include every required input. Probe instructions
are derived through the existing bounded normalized-configuration validator.
No caller-provided filename becomes a host path or overrides a role.

The plan accounts for all input bytes, including generated probe JSON, against
the local aggregate staging maximum. At most 250 dependencies leave room for
the six fixed inputs within the existing 256-file staging limit. The signed
archive layout and expansion ceilings are available separately; they are not a
claim that expanded files fit the guest workspace quota.

Accessors return copies. The plan binds the complete deterministic job bytes and
refuses a changed job. Returned input metadata contains no download/upload URLs,
credentials or commands. Descriptor contents remain untrusted until copied and
hash-verified; an identity plan is not proof that a file has been read.

This does not expose a root service, produce a guest command, grant current
network authority or relax the legacy Paper network-v2 fence. Root service
dispatch, protected descriptor ownership, measured guest archive materialization,
secret/event handoff and real Paper acceptance remain required integration work.
Tests verify signed-runtime identity, input roles/hashes, aggregate limits,
immutable copies and malformed or swapped job inventories without running JARs.
