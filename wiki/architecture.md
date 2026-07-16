# Current architecture

**Updated:** 2026-07-16
**Status:** M1–M4 reference profiles implemented; M4 is fixed no-model L2 observe-only

## TL;DR

The repository implements canonical contracts/compiler plus an embedded default-deny policy, trusted evidence ingestion, durable Linux/WSL repository reads, exact-approved one-file controlled writes, governed model-adapter identities, direct-egress isolation, signed local/cloud evaluation evidence, and one fixed no-model `wiki-health-check` promoted only through L2. Cloud aliases are observable routing identities, not immutable-weight pins.

## Implemented

```text
.ai YAML contracts
→ JSON Schema and cross-file validation
→ eco compiler
→ owned vendor projections
→ CI drift and unit tests
→ pure PolicyEngine
→ typed EmbeddedOrchestrator
→ SQLite event/plan/budget/operation authority
→ filesystem-only Linux broker + private artifact CAS
→ separate authenticated write authority + human approval trust store
→ Linux/WSL one-file CAS apply, rollback and restart recovery
→ trusted snapshot/observation ingestion
→ governed local/cloud adapters (observable identity boundary)
→ Linux/WSL network-denied launcher
→ signed cross-deployment evaluation
→ fixed NoModelRunPlan + private HMAC journal
→ deterministic three-page wiki health report
→ five-attempt + zero-read replay L0–L2 promotion gate
```

## Explicitly not implemented

- endpoint-specific network allowlist backend;
- Windows/macOS executable broker and isolation backends;
- Windows/macOS controlled-write backends;
- autonomous model router;
- durable replay registry for evidence envelopes;
- asymmetric evidence signatures;
- cryptographic remote issuer identity;
- multi-user WebAuthn/OIDC approval service and asymmetric approval identity;
- caller-independent external anchor storage.
- full-wiki link/staleness lint, scheduler, autonomous retry, and L3–L5 loop authority.

The implemented M2–M4 boundary has negative, concurrency, process-crash, artifact, migration, backup, key-rotation, anchor, adapter, isolation, evidence, parity, exact-approval, CAS-recovery, no-model replay, state-integrity, repository-nonmutation, and promotion tests. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md), [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md), and [M4 report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md).

## Current M4 vertical slice

`eco run wiki-health-check` manually verifies exactly three externally signed D0/P1 wiki pages with zero model/network/write budget. Each broker attempt has a durable `started` ambiguity fence; only pre-start recovery may reauthorize, while an uncertain post-start outcome fails without rereading. The deadline survives recovery and policy freshness advances during the run. `eco eval wiki-health-check` requires five stable independent journals and a zero-read replay, then marks only L0–L2 eligible. Reports/journals contain no raw path or content. See [M4 no-model wiki health](../docs/architecture/no-model-wiki-health.md).

The next vertical slice is M5 team identity/signed-policy/RBAC. Scheduling, autonomous retry, full-wiki lint, and every L3–L5 profile remain separate future gates. Every new write backend must independently preserve root/path semantics, exact approval, durable recovery, M2 trusted evidence, isolation, no fallback, and parity.

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Roadmap](roadmap.md)
