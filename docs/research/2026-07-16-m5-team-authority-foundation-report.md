# M5.0–M5.2 team-authority foundation report

**Date:** 2026-07-16

**Verdict:** the identity-contract and signed deny-all policy foundation is implemented and regression-safe. It is ready for M5.3 RBAC design/implementation, but it is not a complete M5 authority system.

## Implemented scope

- Separate `authority.ai.ecosystem/v1alpha1` namespace and schema digest.
- Closed `TeamIdentity`, `PrincipalIdentity`, `MembershipBinding`, `IdentityKey` and `TeamPolicyBundle` schemas.
- Domain-separated self-excluding record digests, deterministic membership IDs, raw-key SHA-256 identity and strict canonical validity rules.
- Recursive bundle validation for kinds, ordering, uniqueness, exact digest bindings, controller relationships and the team policy-signing key.
- Caller-supplied external immutable trust-anchor model and exact Ed25519 envelope verification using `cryptography`; anchor provenance is not claimed in M5.2.
- Strict canonical JSON, duplicate-key denial, fixed algorithm/key/signature size, subject/team/project binding and time bounds.
- Immutable verification result that permanently reports no activation or authority.
- Descriptor-based diagnostic CLI file reads, project-controlled trust-anchor denial and explicit `relative-to-supplied-anchor` result semantics.
- Dependency lock update for `cryptography`, `cffi` and `pycparser`.

## Multi-agent review

Three independent read-only reviews covered identity/crypto contracts, shared-state architecture and threat/adversarial testing. Their P0 findings were applied:

- split runtime and authority schema registries so M4 durable snapshots remain compatible;
- define the record-digest projection explicitly instead of hashing a self-referential field;
- reject key self-bootstrap and keep signing external;
- call predecessor links structural, not replay protection;
- make all M5.2 CLI output verification-only;
- preserve the existing `PolicyEngine` as the final safety intersection for M5.3;
- reserve a new SQLite team-authority store for activation/revocation/quorum instead of stretching process-local stores.

## Verification evidence

| Gate | Result |
|---|---|
| Focused identity, signature and CLI suite | 24 tests pass |
| Full pytest regression | 405 tests pass |
| M4 runtime schema digest | Unchanged at `d7ab8041...316d9d` |
| Python compile | Pass |
| Lock synchronization | `uv lock` + `uv sync --extra test` pass |
| Canonical/duplicate JSON, tamper, wrong anchor/team/project/key, time and file-alias negatives | Pass |
| Repository/external-file byte+mtime no-write assertion for verify | Pass |

## Exact non-claims

This slice does not establish the newest identity or policy revision, effective membership, revocation freshness, RBAC permission, active team policy, shared writer authority, remote identity, human presence, key hardware provenance, quorum approval or runtime access. It does not modify or supersede `.ai/trust.yaml` and does not convert M4 evidence into team authority.

## Handoff to M5.3

M5.3 must add a bounded policy vocabulary without introducing a second allow oracle. Effective authorization must be an intersection of authenticated current team state, team allow/no deny, the existing `PolicyEngine` safety decision, and an exact later approval permit where required. Wildcards, role inheritance, implicit administrator roles and arbitrary policy expression languages remain out of scope.
