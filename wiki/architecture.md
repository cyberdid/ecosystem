# Current architecture

**Updated:** 2026-07-15
**Status:** M1 compiler and embedded M2 read-only reference profile implemented

## TL;DR

The repository implements canonical contracts/compiler plus an embedded default-deny policy, trusted evidence ingestion, durable Linux/WSL repository reads, governed model-adapter identities, direct-egress isolation, and signed local/cloud evaluation evidence. Cloud aliases are observable routing identities, not immutable-weight pins.

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
→ trusted snapshot/observation ingestion
→ governed local/cloud adapters (observable identity boundary)
→ Linux/WSL network-denied launcher
→ signed cross-deployment evaluation
```

## Explicitly not implemented

- endpoint-specific network allowlist backend;
- Windows/macOS executable broker and isolation backends;
- controlled-write sandbox execution;
- autonomous model router;
- durable replay registry for evidence envelopes;
- asymmetric evidence signatures;
- cryptographic remote issuer identity;
- approvals;
- caller-independent external anchor storage.

The implemented M2 boundary has negative, concurrency, process-crash, artifact, migration, backup, key-rotation, anchor, adapter, isolation, evidence, and parity tests. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md).

## Next vertical slice

Begin M3 with narrowly controlled workspace writes, explicit approvals, idempotency, rollback, and platform adapters. Every new backend must preserve the M2 trusted-evidence, isolation, no-fallback, and parity gates.

The first automation loop remains `wiki-health-check` in L2 observe/report-only mode. Scheduling and autonomous retries are added only after the manual command, deterministic gate, bounded state, and repeated-run evaluation are reliable. See [Loop engineering](loops.md).

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Roadmap](roadmap.md)
