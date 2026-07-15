# Current architecture

**Updated:** 2026-07-15
**Status:** M1 compiler, embedded M2 reads, and bounded M3 Linux/WSL controlled writes implemented

## TL;DR

The repository implements canonical contracts/compiler plus an embedded default-deny policy, trusted evidence ingestion, durable Linux/WSL repository reads, exact-approved one-file controlled writes, governed model-adapter identities, direct-egress isolation, and signed local/cloud evaluation evidence. Cloud aliases are observable routing identities, not immutable-weight pins.

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

The implemented M2/M3 boundary has negative, concurrency, process-crash, artifact, migration, backup, key-rotation, anchor, adapter, isolation, evidence, parity, exact-approval and CAS-recovery tests. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md) and [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md).

## Next vertical slice

Begin M4 with repeated L0–L4 evaluation around the bounded M3 primitive. Every new write backend must separately preserve root/path semantics, exact approval, durable recovery, M2 trusted-evidence, isolation, no-fallback and parity gates.

The first automation loop remains `wiki-health-check` in L2 observe/report-only mode. Scheduling and autonomous retries are added only after the manual command, deterministic gate, bounded state, and repeated-run evaluation are reliable. See [Loop engineering](loops.md).

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Roadmap](roadmap.md)
