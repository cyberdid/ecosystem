# M5 team authority

**Status:** M5.0–M5.7 implemented for the bounded same-host reference profile.

**Updated:** 2026-07-16

## Purpose

M5 turns portable signed team declarations into a shared authority that can safely narrow, but never expand, the existing runtime policy. It is independent of a particular model, client, cloud, or laptop.

```text
external Ed25519 trust anchor
→ signed team/policy bundle
→ private SQLite activation authority
→ current actor and membership resolution
→ exact Ed25519 workload-authentication assertion
→ exact ToolRequest-bound trusted PolicyEngine decision
→ in-memory or durable single-use runtime claim
→ exact signed team-access candidate
→ optional authority-issued quorum permit
→ one atomic effect-boundary recheck
```

A signature authenticates exact bytes relative to an externally supplied anchor. Only activation in the authority store establishes the current revision. Neither a valid bundle nor team access can turn a runtime deny into an allow.

## Implemented slices

| Slice | Delivered contract |
|---|---|
| M5.0–M5.2 | Closed team, principal, membership, public-key and policy-bundle records; canonical digests; externally anchored Ed25519 verification; deny-all bootstrap |
| M5.3 | Exact role/action/resource/constraint access policy with explicit-deny precedence and no wildcard or inheritance semantics |
| M5.4 | Private HMAC-authenticated SQLite authority, monotonic revision activation, predecessor CAS, epochs, snapshots and multi-process serialization |
| M5.5 | Principal/membership/key/policy revocation, emergency deny, quorum-protected recovery, dual-anchor rotation and successor-generation migration |
| M5.6 | Signed approval profiles, requests and votes; distinct-human quorum; requester separation; exact single-use action permits |
| M5.7 | Public doctor/activation CLI, coherent verified backup, reopen/tamper checks, Linux/macOS/Windows contract tests, documentation and `0.7.0` release metadata |

## Trust and storage boundary

The project never stores a private signing key. The operator supplies:

- an external immutable Ed25519 trust-anchor document;
- a 32-byte HMAC secret through `ECO_TEAM_AUTHORITY_HMAC_HEX`;
- an absolute authority-database path outside the governed project;
- externally signed canonical policy envelopes, actor assertions and approval votes.

The authority database authenticates its state, epochs, event chain, permit ledger, recovery evidence, backup snapshot and generation lineage. Opening an unsafe, aliased, linked, permission-exposed or modified store fails closed on supported POSIX hosts. Windows CI proves contract behavior, not native Windows ACL enforcement.

Every live authorization rechecks the raw active envelope, its HMAC, canonical digest and Ed25519 signature. Catalog lookup proves that an identity exists; it is not authentication. A live actor must additionally supply a closed Ed25519 assertion from the principal's active `workload-authentication` key. The assertion binds team, project, principal, membership, exact authority snapshot, audience, operation digest, nonce and a five-minute-or-shorter validity window. Caller-supplied principal or membership labels alone never create actor authority.

## Activation and currentness

Activation runs under `BEGIN IMMEDIATE` and requires all of the following:

1. exact store/team/project identity;
2. a valid envelope under the external trust anchor;
3. revision 1 with the zero predecessor, or exact previous revision and digest;
4. an unused activation ID;
5. a matching current snapshot CAS;
6. no revoked trust component.

Successful activation advances the authority epoch and creates a new authenticated snapshot. Competing writers serialize; stale activation attempts leave state unchanged. A cryptographically valid but inactive policy is never current authority.

## Access semantics

`TeamAccessPolicy` supports only exact actions and exact resource identities. There are no wildcards, implicit inheritance, substring matches, or “closest” policies. Constraints are evaluated inside the same matching statement. An explicit matching deny takes precedence over allow.

Team access returns only an `ALLOW_CANDIDATE`. Final authorization is the intersection of:

```text
trusted current PolicyEngine allow
AND current signed team-access allow
AND active non-revoked actor/membership/key
AND emergency-deny is off
AND exact authority-issued permit when action class is A2
```

The M5 reference profile hard-denies A3, A4 and D4. It creates no new model, network, scheduling, command, delete, rename or batch authority.

The executable M5 gate is narrower than the access-policy vocabulary. It currently supports only `repository.read` and `repository.write`, each bound to an exact `ToolRequest` kind, id, full semantic digest and matching `spec.toolId`. Other action/resource shapes fail closed until an action-specific extractor is implemented. The runtime allow must be issued by a concrete `PolicyEngine` adapter and is consumed exactly once before permit consumption or the effect callback. The durable adapter additionally requires the same decision to have been issued into `SQLiteRuntimeStore`; replay remains denied after reopen. Because the runtime and team stores are separate SQLite authorities, a later team-state race may conservatively burn the runtime claim, but it cannot create an effect.

## Approvals and separation of duties

An approval profile is part of the signed active bundle. A request binds the exact policy digest, authority/revocation epoch, requester, action, operation, resource digest and expiry. Votes are canonical Ed25519 signatures by active human approval keys.

The authority requires:

- the profile's exact quorum and required role;
- distinct principals, not merely distinct keys;
- requester/approver separation;
- exact approve votes for the same request;
- current non-revoked human principals, memberships and keys;
- an unexpired request under the current policy and revocation epoch.

The resulting permit is recorded by the authority, bound to one exact effect and consumed once. A valid-looking permit dataclass constructed by a caller is not authority.

## Revocation, emergency recovery and rotation

Revocation is exact and epoch-bound. Critical revocations invalidate live authorization immediately. `effect_guard` repeats the live-state check at the effect boundary, closing the window between planning and mutation.

Emergency deny blocks ordinary authorization, permit issue/consume and effects. A plain disable call is rejected. Recovery requires a signed `emergency-recovery` profile, a request bound to the exact emergency head and epoch, an Ed25519 requester assertion bound to that exact recovery request, and at least two distinct eligible human approvers excluding the authenticated requester. Verification and disable occur in one transaction and persist authenticated recovery evidence.

Trust-anchor rotation requires possession of both old and new Ed25519 private keys. The canonical rotation envelope is signed by both anchors. The predecessor first reserves one target-bound commitment and enters `rotation-pending`, fencing ordinary use. A pending successor imports the exact authenticated revocation epoch/head/set, records lineage, activates revision 1, is atomically published without replacement, and only then becomes active; the predecessor becomes `retired`. Exact resume is fail-closed after a crash, while replay to a second target is rejected. Completed backup copies remain movable evidence, so this protocol prevents API-level rotation forks rather than claiming protection from an operator who manually clones the database and its secrets.

## Operator CLI

The CLI never accepts the HMAC secret as an argument and does not print it, raw envelopes, key material or database paths.

```bash
export ECO_TEAM_AUTHORITY_HMAC_HEX='<64 hexadecimal characters>'
export EXPECTED_AUTHORITY_SNAPSHOT_DIGEST='<digest from eco team doctor --json>'

eco team activate \
  --database /external/private/team-authority.sqlite3 \
  --trust-anchor /external/private/team-anchor.json \
  --project example-project \
  --audit-key-id audit-key-1 \
  --store-id authority-store-1 \
  --envelope /external/inbox/policy-envelope.json \
  --activation-id activation-0001 \
  --expected-revision 0 \
  --expected-digest 0000000000000000000000000000000000000000000000000000000000000000 \
  --expected-snapshot-digest "$EXPECTED_AUTHORITY_SNAPSHOT_DIGEST" \
  --apply --json

eco team doctor \
  --database /external/private/team-authority.sqlite3 \
  --trust-anchor /external/private/team-anchor.json \
  --project example-project \
  --audit-key-id audit-key-1 \
  --store-id authority-store-1 \
  --json
```

`activate` is the only mutating public command and requires the explicit `--apply` confirmation. `doctor` opens and verifies existing state without granting runtime authority.

## Backup and recovery runbook

1. Put the database and trust anchor in an operator-controlled private external directory.
2. Keep the HMAC secret and Ed25519 private keys in separate secret custody; never commit them.
3. Use the exported API `SQLiteTeamAuthority.backup_to(destination, expected_snapshot_digest=..., now=..., forbidden_root=...)` to create a coherent private SQLite backup while writers may exist.
4. Reopen the backup with the same external anchor and HMAC secret; require the exact returned snapshot. Before using a restored active copy, fence/decommission the original authority path—backup is not distributed consensus or an active-active mechanism.
5. Test emergency-recovery quorum and successor-generation rotation with non-production identities before production use.
6. Preserve the predecessor store and dual-signed rotation evidence after migration.
7. Treat any corruption, topology, HMAC, signature, lineage or snapshot error as a stop condition, not a repair suggestion.

## Compatibility and proof boundary

M5 authority schemas use a separate registry. The M4 runtime schema bundle remains unchanged:

```text
d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d
```

M5 proves a local same-host reference authority. PostgreSQL or a network control plane, SSO/OIDC/WebAuthn, KMS/HSM/Vault integration, HA consensus, multi-region operation, remote attestation, native Windows ACL enforcement, native macOS/Windows runtime-security backends, and A3/A4 action profiles remain future work. ADR-027 re-sequences this unchanged backlog from the former M6 to M7 so M6 can deliver functional orchestration first.

See the [M5 completion report](../research/2026-07-16-m5-team-authority-completion-report.md), [ADR-026](../decisions/README.md#adr-026--team-authority-is-a-narrowing-same-host-authority-with-generation-based-rotation), and [ADR-027](../decisions/README.md#adr-027--prioritize-functional-orchestration-before-enterprise-backends).
