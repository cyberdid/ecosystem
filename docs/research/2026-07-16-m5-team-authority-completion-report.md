# M5 team authority completion report

**Date:** 2026-07-16

**Release:** `0.7.0`

**Status:** complete for the bounded same-host reference profile; hosted CI run [29513118749](https://github.com/Pylypko1021/ecosystem/actions/runs/29513118749) passed at implementation commit `527a64030ea384651a2bbd700f72b0fc999beac9`.

## Executive result

M5 delivers a model-agnostic team-authority layer that can be embedded into different projects and AI clients without trusting project-owned labels or creating a second allow oracle. It combines externally anchored signed identity/policy, exact narrowing access decisions, durable activation/currentness, revocation, emergency recovery, quorum approvals, single-use permits, coherent backup and dual-signed generation migration.

The implementation is deliberately bounded. It is a local same-host authority built on a private HMAC-authenticated SQLite store. It is not an enterprise network control plane, SSO system, KMS, consensus cluster or native cross-platform runtime-security backend.

## Multi-agent method

Specialized agents independently covered:

1. identity, schema and policy semantics;
2. shared SQLite authority and transaction behavior;
3. quorum approvals and separation of duties;
4. adversarial integration/threat review;
5. dual-possession Ed25519 rotation;
6. emergency-recovery design;
7. safe CLI and activation boundary.

The root integration pass then corrected cross-module assumptions and reran the complete regression suite. The most important audit corrections were: live signature/HMAC revalidation, Ed25519 actor proof in addition to signed-catalog lookup, exact ToolRequest/action/resource binding, a concrete single-use `PolicyEngine` intersection, optional durable runtime-store claims, exact approval-profile binding, authority-issued rather than caller-constructible permits, effect-boundary rechecks, human-only quorum roots, authenticated-requester quorum recovery, and non-destructive successor-generation rotation.

## Delivered components

| Area | Main implementation | Security property |
|---|---|---|
| Identity and bundle | `team_identity.py`, closed authority schemas | Canonical digest binding and external Ed25519 verification without self-bootstrap |
| Access policy | `team_access.py`, `team-access-policy.schema.json` | Exact matching, explicit-deny precedence, no wildcards/inheritance, A3/A4/D4 hard deny |
| Shared authority | `team_authority.py` | Authenticated durable state, activation CAS, epochs, snapshots, serialization, revocation and permit ledger |
| Approval | `team_approval.py`, `team-approval.schema.json` | Signed exact requests/votes, distinct-human quorum, requester separation, bounded expiry |
| Runtime intersection | `team_actor.py`, `team_runtime.py` | Exact Ed25519 actor proof AND exact single-use PolicyEngine/ToolRequest claim AND team candidate AND authority-issued permit |
| Rotation/migration | `team_rotation.py`, `team_migration.py`, rotation schema | Old+new key possession and immutable predecessor/successor lineage |
| CLI | `eco_cli/team.py`, `eco_cli/cli.py` | External safe paths, secret via environment, sanitized doctor and explicit apply activation |
| Release/CI | `pyproject.toml`, `uv.lock`, workflow matrix | `0.7.0`, full Linux regression, focused macOS/Windows M5 contract checks |

## Threat-control matrix

| Threat | Implemented control | Remaining boundary |
|---|---|---|
| Project self-signs its own authority | Verification key comes from an external `PolicyTrustAnchor`; embedded keys only bind identity | External anchor provisioning and custody are operational responsibilities |
| Replay of an old valid policy | Monotonic activation revision, exact predecessor digest, snapshot CAS and authenticated activation history | Distributed consensus is not provided |
| Caller invents actor or role | Runtime resolves signed state and verifies an exact Ed25519 `workload-authentication` assertion | SSO/OIDC/WebAuthn federation is M6 |
| Team policy expands runtime permission | Team result is only an allow candidate intersected with an exact, single-use current `PolicyEngine` decision; executable M5 actions are limited to repository read/write ToolRequests | Other action-specific runtime extractors and A3/A4 remain denied |
| Permit forgery | Authority ledger must contain the exact issued permit; caller-created dataclasses have no authority | Remote third-party permit service is absent |
| Same person satisfies quorum twice | Votes require distinct eligible human principal IDs; keys alone are insufficient | Organizational independence cannot be proven locally |
| Requester self-approves | The requester is authenticated for the exact operation and excluded from eligible voters | Enterprise delegation workflows are absent |
| Revocation races an effect | Current epochs and revocations are checked again in `effect_guard` | Distributed external effects require a remote transactional adapter |
| Lockdown is casually disabled | Generic disable is rejected; exact signed recovery request plus at least two distinct human approvals is required atomically | Offline break-glass root is not implemented |
| Old key rewrites history after rotation | Dual old/new signatures plus new successor store and authenticated lineage; old store is retained | HSM-backed ceremony is external |
| Live database is copied inconsistently | SQLite backup API produces a coherent private backup and exact reopen snapshot | Cross-region backup orchestration is M6 |
| Database rows are edited | HMAC state/event verification plus raw envelope digest and signature revalidation fail closed | HMAC secret compromise is outside this local trust boundary |

## Authorization invariant

An effect is allowed only when all terms are true at the effect boundary:

```text
trusted_runtime_decision.allow
∧ current_team_access_candidate.allow
∧ exact_active_actor_and_membership
∧ no_applicable_revocation
∧ emergency_deny = false
∧ exact_current_policy_and_epochs
∧ authority_issued_and_unconsumed_A2_permit_if_required
```

No single schema, signature, role, vote, permit object or database row is sufficient by itself.

## Verification evidence

Local completion gate:

| Check | Result |
|---|---|
| `pytest -q` | 474 passed |
| `python -m unittest discover -s tests -q` | 474 passed |
| `eco validate` | passed |
| `eco render --check` | passed |
| `eco doctor` | passed |
| `python -m compileall` | passed |
| `git diff --check` | passed |
| CLI version | `eco 0.7.0` |
| Built-wheel install/import smoke | passed; M5 modules and all three new schemas present |
| Native Windows distribution regression | 19 passed, 2 skipped platform-only primitives |
| Hosted GitHub Actions | Linux full/offline-wheel plus focused macOS/Windows passed in run `29513118749` at `527a640` |

Adversarial tests cover malformed/ambiguous schemas, signature and digest tampering, actor impersonation and assertion substitution, runtime-decision replay/concurrency/reopen, stale CAS, competing SQLite writers, post-open revocation tamper, revocation carry-forward/reintroduction, emergency denial and authenticated recovery, insufficient/duplicate/requester/wrong-role approvals, forged permits, effect-boundary changes, unsafe store and input paths, backup target races, dual-anchor rotation, crash-resume, sequential/concurrent successor-fork attempts and lineage tamper.

The first hosted release run exposed a latent Windows-only distribution-reader defect: CRT text mode translated CRLF and treated byte `0x1A` as EOF, so a valid wheel appeared truncated. Both the installed and standalone readers now request `O_BINARY`; all existing bounded-read, regular-file, one-link, reparse-point and before/open/after identity checks remain in place. A byte-exact CRLF/`0x1A` digest regression passes on native Windows and POSIX.

M5 authority schemas remain separate from M4 runtime schemas. The unchanged runtime schema bundle digest is:

```text
d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d
```

## Portability statement

The authority and contract code is platform-neutral Python and focused M5 tests run in Linux/macOS/Windows CI. The strong private-file permission claim is POSIX-bounded; hosted Windows proves API/schema/transaction behavior, not a native Windows ACL security backend. Existing Linux/WSL read, isolation and write-broker proof remains unchanged.

## M5 exit criteria

1. Signed team identity and policy are externally anchored and closed — passed.
2. Access rules only narrow the existing runtime policy — passed.
3. Currentness is durable, monotonic and transactionally activated — passed.
4. Live identity, policy, epoch and revocation state are revalidated — passed.
5. A2 effects use exact distinct-human quorum and authority-issued single-use permits — passed.
6. Emergency deny requires independently approved atomic recovery — passed.
7. Trust-anchor change preserves history through dual-signed generation migration — passed.
8. Backup, doctor, activation CLI, cross-platform contract tests and release metadata are present — passed.
9. Earlier runtime contracts and complete regressions remain intact — passed.

## M6 handoff

M6 should add backends, not silently broaden this reference authority. Candidate tracks are PostgreSQL/network authority with HA and consensus; SSO/OIDC/WebAuthn authentication; KMS/HSM/Vault signing and HMAC custody; remote effect adapters and attestation; native Windows/macOS security backends; enterprise delegation; multi-region disaster recovery; and separately threat-modeled A3/A4 profiles.

Each backend must preserve exact canonical bindings, narrowing-only authorization, deny precedence, epoch/revocation freshness, quorum independence, effect fencing and explicit non-claims.

## References

- [M5 architecture](../architecture/team-authority.md)
- [Operations runbook](../operations/team-authority-runbook.md)
- [M5.0–M5.2 foundation report](2026-07-16-m5-team-authority-foundation-report.md)
- [ADR-025 and ADR-026](../decisions/README.md)
