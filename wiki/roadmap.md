# Roadmap

**Updated:** 2026-07-14

| Milestone | Deliverable | Status |
|---|---|---|
| M0 | Inventory, research, threat hypotheses, baseline tasks | Complete enough to start; benchmarks remain open |
| M1 | Schemas, CLI, projections, audit, lock, tests | Implemented |
| M2 | Read-only PEP/broker, local+cloud adapters, sanitized run events | Next |
| M3 | Controlled writes, sandbox, approvals, idempotency | Pending |
| M4 | L0–L4 evals and promotion | Pending |
| M5 | Team state, signed policy, RBAC | Deferred |
| M6 | Enterprise topology options | Deferred |

## M2 exit criteria

1. Agent/client processes have no provider/tool credentials.
2. Direct egress bypass test is denied.
3. One DGX and one cloud deployment have exact revision records.
4. Unsupported capability returns a typed failure.
5. Read-only tool access stays inside the repository boundary.
6. Sensitive content is absent from default telemetry/audit output.
7. The same project evaluation runs on both deployments.

## Non-goals for M2

- external writes;
- automatic fallback after safety/data denial;
- A2A;
- Temporal;
- Kubernetes;
- multi-agent orchestration;
- production claims.

## Loop rollout

| Phase | Allowed loop behavior | Dependency |
|---|---|---|
| Current / M1 | Manual commands and documented candidates | Existing compiler and validation |
| M2 | L2 observe/report-only loop prototype | Read-only PEP, sanitized events, negative bypass tests |
| M3 | L3 proposals and narrowly approved L4 writes | Sandbox, approvals, idempotency and rollback |
| M4 | Promotion by repeated-run L0–L4 evaluations | Quality, safety, cost and recovery thresholds |

The first candidate is `wiki-health-check`; `ml-autoresearch` follows only after experiment isolation, immutable evaluation, reproducibility and DGX resource limits are enforced. See [Loop engineering](loops.md).

## Sources

- [Architecture](../docs/architecture/README.md)
- [Decision register](../docs/decisions/README.md)
- [Loop engineering](loops.md)
