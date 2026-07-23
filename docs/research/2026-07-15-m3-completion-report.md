# M3 controlled-write completion report

**Date:** 2026-07-15

**Verdict:** complete for the bounded embedded Linux/WSL one-file `create`/`replace` profile

**Regression gate:** 258/258 `unittest` tests

## What is complete

M3 adds a portable logical `repository.write` capability with one proven backend. It can create one absent UTF-8 regular file or replace one exact existing UTF-8 regular file below an already existing directory. The action class is A2. The governed workspace is mutated only by the trusted Linux/WSL broker after policy, human approval, durable PREPARE, rollback readiness and exact filesystem preconditions succeed.

This is an enforcement primitive, not general repository autonomy. It does not implement delete, rename, directory creation, batch transactions, arbitrary commands, A3/A4 external actions, live-root promotion, scheduling or production multi-user approval.

## Implemented authority chain

```text
active immutable RunPlan
→ exact repository.write ToolRequest
→ exact unexpired PolicyDecision allow
→ WorkspaceChangeProposal
→ authenticated expiring human approval
→ atomic PREPARE
   - consume approval once
   - consume policy decision once
   - acquire target lock
   - bind idempotency key
   - persist fenced lease
   - bind private-CAS recovery record
→ broker verifies exact before-state
→ before-image and complete recovery bundle become durable
→ rollback_ready
→ applying: fsync and exact revalidation
→ durable commit_ready permit under active plan + live fence
→ descriptor-anchored atomic apply
→ postcondition validation
→ committed or CAS rollback
```

The first profile requires a dedicated write-only RunPlan. This lets the separate M3 authority enforce the plan's complete `maxToolRequests` budget without double-counting or bypass through the M2 read journal; mixed read/write plans are rejected.

The plan, policy decision, approval and write authority remain separate. A policy allow does not impersonate a human. A human approval cannot authorize a policy-denied request. The local journal HMAC authenticates the embedded store but cannot manufacture the independently configured human signature.

## Exact bindings

The approved authority subject binds all of the following by canonical digest:

- write-store identity, project, run and active plan;
- exact policy allow decision;
- repository root identity and base snapshot;
- A2 operation kind;
- keyed target reference, without putting the raw path in SQLite;
- exact before-state or absence;
- candidate artifact digest, byte length, data class, trust, mode and availability proof;
- rollback manifest;
- human-visible display/preview digest;
- byte, file, operation and approval-expiry limits.

Any substitution changes the subject. The durable proposal is reloaded during execution and compared to the complete live bundle, closing object-replacement attacks that preserve only an identifier or signed subject string.

## Filesystem enforcement

The Linux/WSL broker pins the governed root by descriptor and root-identity digest. Repository-relative paths are canonicalized and resolved below that descriptor using `openat2` with no symlinks, magic links, mount crossing or escape. Protected paths, missing parents, directories, special files, hardlinks, binary/NUL content, invalid UTF-8, excessive size and changed file identity fail closed.

For `create`, the exact precondition is absence. For `replace`, the file digest, byte length and mode must match the approved before-state. Candidate bytes are copied from authenticated CAS into an exclusive same-directory temporary file, validated, fsynced and rechecked. The broker performs a no-replace create or exchange replace, fsyncs the parent directory, reopens the result and verifies the exact after-state.

Rollback is another compare-and-swap operation. It removes an M3-created file or restores the captured before-image only while the live file still equals the exact M3 after-image. Unrelated edits are never overwritten.

## Durability, replay and recovery

M3 uses a separate authenticated SQLite authority instead of silently migrating the proven M2 schema-v3 read journal across a new approval boundary. Approval consumption, policy-decision consumption, operation creation and target-lock acquisition share one `BEGIN IMMEDIATE` transaction. Idempotency is scoped to run plus a domain-separated key digest. A conflicting reuse fails; an exact terminal retry returns historical state even after approval and policy expiry.

SQLite, WAL and audit records contain no raw repository path or file content. A private CAS outside the governed repository stores candidate bytes, before-images and a canonical recovery bundle. SQLite retains only the opaque CAS reference, SHA-256, byte length and semantic digest. `rollback_ready` atomically replaces the initial recovery reference with the complete one before broker mutation.

After process loss, a new worker:

1. waits for or detects expiry of the old lease;
2. claims the operation with a higher fencing epoch;
3. reopens and fully hashes the CAS recovery object;
4. re-verifies operation, proposal, approval, policy, root, target and artifact bindings;
5. removes only the exact authority-bound temporary name left by an interrupted apply/rollback;
6. observes the live target through the broker;
7. marks exact before-state as terminal failed without target mutation;
8. rolls exact after-state back through the pre-authorized CAS protocol;
9. leaves every unrelated state as `recovery_required` with a durable conflict reason.

Recovery never turns ambiguity into success. Transition timestamps advance by monotonic elapsed time so a slow postcondition cannot keep reusing the PREPARE timestamp beyond its lease. The runtime store holds a cross-connection `BEGIN IMMEDIATE` guard while the final active-plan/lease check persists `commit_ready`, so run termination cannot race permit issuance. This is a non-revocable one-shot permit, not a revocable read-check; if time or process ownership changes inside the kernel-commit window, recovery reconciles the durable permit against the exact filesystem state and compensates an installed after-image.

## Evidence matrix

| Claim | Principal implementation | Negative or recovery evidence |
|---|---|---|
| Typed A2 contract | M3 JSON Schemas and `contracts.py` | unknown fields, bad operation/before combinations and unsafe durable fields rejected |
| Exact policy | `policy.py` | sandbox/action mismatch, protected path, changed digest and data-class mismatch denied |
| Exact human approval | `approval.py` | wrong subject, expiry, key/human/assurance mismatch, tamper and nonce replay rejected |
| Atomic authority | `change_store.py` | concurrent approval use, policy reuse, target contention, stale fencing and audit tamper tested |
| Root/path boundary | `write_broker.py` | traversal, symlink/hardlink, parent swap, mount/profile, special-file and protected-path tests |
| Atomic apply | `write_broker.py` | faults before commit leave target unchanged; two creators have one winner |
| CAS rollback | `write_broker.py` | exact before restored; changed after-state and tampered backup proof refused |
| Bundle substitution defense | `write_orchestrator.py` | signed authority subject cannot be reused for another path/content |
| Active authority composition | `write_orchestrator.py` | plan/snapshot/broker root mismatch and inactive-plan checks fail before mutation |
| Historical idempotency | `write_orchestrator.py` | terminal replay after policy/approval expiry has one effect |
| Process-loss recovery | CAS + change authority + orchestrator | injected crash after atomic commit, full reopen, fenced claim and rollback to before-state |
| Hard-kill orphan cleanup | broker + authenticated recovery bundle | real fork/process-exit tests after candidate fsync and rollback rename remove only the exact durable temp name |
| Pre-commit authority | runtime guard + change authority + broker callback | concurrent stop is serialized against permit; expiry inside rename leaves durable `commit_ready` and restart recovery rolls back |
| Unified write budget | dedicated write-only plan + change authority | mixed read/write plan rejected; policy decision and each write counted once |
| M2 compatibility | `store.py` legacy bundle allowlist | authenticated pre-M3 M2 schema bundle remains openable |

## Multi-agent review closure

Implementation and review were split across contract/policy, Linux broker, approval/change authority, orchestrator integration and adversarial review roles. The final review found and the implementation closed these material issues:

- signed-subject substitution against another live proposal;
- plan snapshot and broker root mismatch;
- missing durable active-plan requirement;
- non-atomic policy-decision reuse;
- terminal replay failing after approval/decision expiry;
- recovery that detected ambiguity but could not reconstruct after process loss;
- stale transition time and active-plan revocation during slow execution;
- cross-root recovery, split read/write budgets and hard-kill temp leakage.

The fixes have dedicated regression tests. The final safety review is recorded through the repository test evidence and this report; no known P0/P1 issue is accepted as an M3 completion exception.

## Verification gate

The completion gate is:

```text
python -m unittest discover -s tests -v   # 258/258
pytest -q
python -m compileall -q src tests
eco validate
eco render --check
eco doctor
uv lock --check
git diff --check
```

No network or provider credential is required for this deterministic M3 gate.

## Exact limitations

- Backend proof is Linux/WSL-specific and depends on tested `openat2`/`renameat2` semantics.
- Only one bounded regular UTF-8 file and an existing parent are supported.
- The reference human signer uses configured symmetric HMAC keys. Team use requires an independently authenticated approval service such as WebAuthn/OIDC and operational identity governance.
- Active plan and write authority are separate SQLite databases. The runtime store's `BEGIN IMMEDIATE` guard serializes run termination across connections while the change store persists the fenced `commit_ready` permit. A stop after that permit cannot revoke it; ambiguous completion is reconciled and compensated. Production service composition must preserve this guard/permit/rename ordering at one trusted boundary.
- Recovery requires the write database and private CAS together. A packaged, encrypted, independently tested database-plus-CAS disaster-recovery workflow is not implemented.
- Crash reconciliation persists a deterministic content-free rollback-result digest in the authority; it does not reconstruct and publish a full schema-valid `WorkspaceRollbackReceipt` artifact after process loss.
- Unexpected third-party state remains `recovery_required`; M3 will not overwrite it automatically.
- M3 does not prove production readiness, autonomous-loop quality or safe promotion. Those are M4 evaluation concerns.

## Conclusion

The milestone is complete at its declared boundary: an exact-approved, one-file, Linux/WSL controlled-write primitive with durable authority, atomic apply, conservative rollback, historical idempotency, restart recovery and M2 regression preservation. Broader write powers must be introduced as new profiles with their own contracts, threat models and conformance evidence.
