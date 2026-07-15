# Roadmap

**Updated:** 2026-07-15

| Milestone | Deliverable | Status |
|---|---|---|
| M0 | Inventory, research, threat hypotheses, baseline tasks | Complete enough to start; benchmarks remain open |
| M1 | Schemas, CLI, projections, audit, lock, tests | Implemented |
| M2 | Read-only PEP/broker, local+cloud adapters, sanitized run events | Complete for the embedded Linux/WSL reference profile; 187 tests plus passing live local/cloud evidence |
| M3 | Controlled writes, sandbox boundary, approvals, idempotency | Complete for bounded Linux/WSL one-file create/replace profile; 258 tests |
| M4 | L0–L4 evals and promotion | Pending |
| M5 | Team state, signed policy, RBAC | Deferred |
| M6 | Enterprise topology options | Deferred |

## M2 exit criteria

1. Agent/client processes have no provider/tool credentials.
2. Direct egress bypass test is denied.
3. One local and one cloud deployment have governed identity records at the strongest observable level; a cloud alias is not immutable-weight attestation.
4. Unsupported capability returns a typed failure.
5. Read-only tool access stays inside the repository boundary.
6. Sensitive content is absent from default telemetry/audit output.
7. The same project evaluation runs on both deployments.

All seven criteria pass for the embedded reference profile under ADR-016's observable-identity boundary. The live proof uses governed Ollama/Qwen and broker-owned Claude CLI/Claude Sonnet-alias deployments with suite digest `08d7ee84c62d53c3ae08419623b48cfb6d645fe8c127ddcd090295e194826dd6`. Both signed observations passed trusted ingestion, and the local D0 observation passed the production PolicyEngine gate. Observations expire after 24 hours and must be renewed before current routing or promotion. Retained evaluation artifacts are raw-content-free D0 evidence, not immutable cloud-weight attestation or information-free evidence. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md), [cross-deployment evaluation report](../docs/research/2026-07-15-m2-cross-deployment-evaluation-report.md), and [ADR-016](../docs/decisions/README.md#adr-016--substitute-universal-localcloud-profiles-for-a-dgx-dependency).

## Non-goals for M2

- external writes;
- automatic fallback after safety/data denial;
- A2A;
- Temporal;
- Kubernetes;
- multi-agent orchestration;
- production claims.

## M3 exit criteria

1. A2 write requires an exact active plan, policy allow and authenticated human approval.
2. Approval and policy decision are single-use and bind root, snapshot, path, before-state, candidate, preview, limits and rollback.
3. Only bounded UTF-8 regular-file `create`/`replace` is supported; protected paths and alias/race conditions fail closed.
4. Candidate and before-image are durable before mutation; apply and rollback are descriptor-anchored compare-and-swap operations.
5. Idempotent replay has at most one effect and remains historically observable after authority expiry.
6. Process-loss recovery reopens authenticated private-CAS metadata, fences the old worker and conservatively restores exact before-state.
7. SQLite/WAL/audit contain no raw path or content and are reconciled against an HMAC audit chain.
8. All M2 regression and project gates pass: 258/258 `unittest` tests plus pytest, compile, validate, render, doctor and diff checks.

This profile does not authorize delete, rename, directory creation, multi-file batches, arbitrary commands, A3/A4 actions, live-root promotion or non-Linux backends. See the [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md).

## Loop rollout

| Phase | Allowed loop behavior | Dependency |
|---|---|---|
| Current / M1 | Manual commands and documented candidates | Existing compiler and validation |
| M2 | L2 observe/report-only loop prototype | Read-only PEP, sanitized events, negative bypass tests |
| M3 | L3 proposals and narrowly approved L4 writes | Implemented primitive: exact approval, idempotency, CAS rollback and restart recovery |
| M4 | Promotion by repeated-run L0–L4 evaluations | Quality, safety, cost and recovery thresholds |

The first candidate is `wiki-health-check`; `ml-autoresearch` follows only after experiment isolation, immutable evaluation, reproducibility, and approved local-compute resource limits are enforced. A DGX is one optional local profile, not a dependency. See [Loop engineering](loops.md).

## Sources

- [Architecture](../docs/architecture/README.md)
- [Decision register](../docs/decisions/README.md)
- [Loop engineering](loops.md)
