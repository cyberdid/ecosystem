# Durable runtime store

**Status:** M2.5 complete for the embedded Linux/WSL read-only profile

**Updated:** 2026-07-15

## Implemented boundary

`SQLiteRuntimeStore` now persists sanitized immutable records and owns the authoritative transaction boundary for plan activation and repository-read operations outside the governed repository. Its profile uses:

- SQLite WAL, `synchronous=FULL`, foreign keys, `trusted_schema=OFF`, and `BEGIN IMMEDIATE` writes;
- application/schema/profile pinning, including runtime schema-bundle digest;
- `0600` database and `0700` directory requirements on POSIX;
- immutable record IDs and exact idempotent replay;
- durable decision issuance and atomic consume-by-nonce across separate connections;
- exact plan/profile/policy-snapshot provenance and distinct in-process policy/broker capability tokens;
- one active plan and one absolute deadline per run;
- durable budget limits, counters, input reservations, and conditional no-overspend updates;
- PREPARE, fenced lease/claim, success, failure, recovery scan, and deadline-expiry abort operations;
- canonical JSON bytes and semantic record digests;
- a global SHA-256 audit chain authenticated with HMAC-SHA256 using a key not stored in SQLite;
- authenticated authority revisions for every mutable run/plan/budget/operation/reservation projection;
- schema-v3 full-projection baselines, store-generated immutable run events, deterministic reducer replay, exact producer/issuer and subject/result bindings, and store-generated terminal checkpoints;
- a typed orchestrator over a filesystem-only broker, eliminating the broker's former in-memory policy/budget authority;
- explicit `no_retry` recovery for content-free PREPARE records, exact fencing-epoch resolution, and process-exit recovery tests;
- a private content-addressed artifact store with fsync/atomic install and HMAC availability proofs required before SUCCESS;
- authenticated v2→v3 migration, online backup/verified restore, dual-authenticated audit-key rotation with historical keys, and external anchor export/startup verification;
- bidirectional semantic reconciliation across records, decisions, nonces, plans, budgets, reservations, operations, results, and audit entries;
- verification inside one coherent SQLite read transaction so concurrent writers cannot create a mixed verification view;
- fail-closed reopen on wrong key, incompatible profile, corrupt JSON/digest, broken audit chain, or inconsistent consume state.

The store accepts only allowlisted safe record kinds. `ToolRequest` and `RepositorySnapshot` are deliberately excluded because they contain repository paths. Authority-managed records cannot bypass their transaction APIs through generic `put_record`. Raw paths are represented by a store-scoped, domain-separated HMAC rather than guessable plain SHA-256. Raw prompts, model outputs, tool content, credentials, environment values, arbitrary exceptions, and provider bodies must never enter SQL bindings.

## Transaction records

The following safe records define the future two-phase read protocol:

- `ToolExecutionIntent`: immutable PREPARE record binding plan, tool request, allow decision, idempotency digest, exact snapshot entry, and budget reservation without the raw path;
- `RepositoryReadReceipt`: content-free broker receipt binding operation, request, snapshot, content digest, bytes, D, and P;
- `ToolExecutionOutcome`: exactly one successful receipt/artifact pair or one sanitized error digest;
- `RunCheckpoint`: replayable state/event/budget/open-operation cache with an absolute UTC deadline.

The implemented store flow is:

```text
issue plan + policy allow
→ activate exact plan + initialize absolute deadline and budget
→ PREPARE: consume tool allow + spend tool request + reserve bytes + create intent/lease
→ broker read outside SQLite
→ SUCCESS: exact receipt/artifact/outcome + commit bytes
   or FAILURE: code-owned error/outcome + release bytes
→ expired lease: never repeat I/O in `no_retry`; exact-epoch deterministic failure
→ release byte reservation while preserving the spent tool attempt
```

Raw `untrusted_content` remains ephemeral and is not journaled. The guarantee is exactly-once logical outcome/accounting, not exactly-once physical reading or delivery.

## Recovery and capability boundary

`scan_recoverable_operations` exposes only operation IDs, digests, lease epoch, recovery mode, reserved bytes, and a reason. It cannot reconstruct a raw path by design. The implemented profile is therefore explicitly `no_retry`: after lease expiry, `resolve_unrecoverable_operation` requires the exact observed epoch, records a deterministic failure, and releases only the byte reservation. A future retry profile would require a separate authenticated/encrypted durable payload contract.

Policy and broker capability objects are composition guards inside one Python process. They prevent an untrusted component that merely receives a store reference from issuing decisions, claiming leases, or committing results. They are not durable identities and do not authenticate another process after restart. Multiprocess/team topology requires a signed issuer or authenticated service boundary.

## Operational durability

SQLite owns the complete implemented lifecycle. `RunEventChain` and SQLite replay share the same immutable `RunProjection` and pure reducer. `RepositoryReadBroker` is filesystem-only; `EmbeddedOrchestrator` re-evaluates decisions through its configured policy engine and performs durable PREPARE/COMMIT. Successful artifact bytes are installed and verified before their metadata transaction commits.

Implemented operational ceremonies include authenticated v2→v3 migration, online SQLite backup with immutable semantic verification, verified no-overwrite restore, historical HMAC keyrings, atomic dual-auth key transition, a stable separate path-reference key, and external anchor chains. External anchoring is only as independent and durable as the caller-provided sink.

## Remaining beyond M2.5

- cryptographic multiprocess issuer identity or an authenticated service boundary;
- database-plus-CAS disaster-recovery packaging and retained-reference garbage collection;
- durable evidence replay-ID authority, endpoint allowlists, and power-loss/faulty-storage validation.

See the [M2.5 completion report](../research/2026-07-15-m2.5-completion-report.md) for the evidence matrix and exact proof boundary.
