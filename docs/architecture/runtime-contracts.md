# M2 runtime contracts

**Status:** complete for the embedded M2 Linux/WSL read-only reference profile

**Updated:** 2026-07-15

## Boundary

Canonical `.ai/*.yaml` files describe project intent and allowed topology. Runtime records describe one attempted execution. Runtime records are not additional canonical configuration files and are not written into vendor instruction projections.

```text
canonical configuration snapshot
          +
RunRequest
    ↓
immutable RunPlan
    ↓
PolicyDecision (allow or deny)
    ↓
ToolRequest / future ModelRequest
    ↓
RunEvent chain + ArtifactRecord or ErrorRecord
```

The runtime namespace is `runtime.ai.ecosystem/v1alpha1`; canonical configuration remains `ai.ecosystem/v1alpha1`.

## Implemented record kinds

| Kind | Purpose |
|---|---|
| `RunRequest` | Operator-authored intent, artifact references, constraints, and hard budgets |
| `RunPlan` | Immutable binding of request digest, semantic config digest, route identity, tools, and budgets |
| `ToolRequest` | Untrusted model/runtime proposal bound to a plan digest |
| `PolicyDecision` | Single-use, expiring allow/deny decision bound to the complete subject digest |
| `RunEvent` | Sanitized allowlisted event metadata with sequence and optional previous digest |
| `ArtifactRecord` | Content-free provenance metadata and opaque storage reference |
| `ErrorRecord` | Typed safe failure without raw provider/tool content |
| `AdapterConformanceProfile` | Versioned observed capability evidence bound to exact deployment identity |
| `RepositorySnapshot` | Trusted P1 inventory binding readable paths to root identity, D/P metadata, size, and content digest |
| `ToolExecutionIntent` | Content-free PREPARE binding for one idempotent tool operation and reservation |
| `RepositoryReadReceipt` | Content-free read result metadata bound to intent/request/snapshot |
| `ToolExecutionOutcome` | Exactly one successful receipt/artifact pair or sanitized failure |
| `RunCheckpoint` | Store-generated terminal cache with full reducer projection, history completeness/source, event head, absolute deadline, budget, and open-operation inventory |
| `EndpointBinding` | Time-bounded digest-only binding of an exact deployment identity to a resolved local/cloud endpoint profile |
| `ModelRequest` | Content-bound, budgeted, no-fallback request for one exact deployment and endpoint binding |
| `ModelResult` | Content-free normalized model result, usage, finish reason, and exact request/deployment binding |

The broker-owned `repository.read` argument contract accepts one POSIX-relative path and rejects absolute paths, traversal, URI schemes, backslashes, NULs, extra fields, and invalid types before filesystem access.

## M2 constraints encoded in contracts

- agent and tool network are always `deny`; broker-owned model egress is a separate exact adapter/reference binding;
- maximum action class is A0 or A1;
- automatic fallback is forbidden;
- cost uses integer micro-USD, not floating-point currency;
- task instructions and inputs are artifact references, not audit payloads;
- policy decisions have no approval effect in M2;
- artifact locations are opaque `artifact://` references;
- error details and event metrics are allowlisted;
- unknown fields and record kinds fail closed;
- validation errors never echo offending untrusted values.

## Implemented in-process state model

```text
RECEIVED
→ VALIDATED
→ PLANNED
→ AUTHORIZED
→ RUNNING
→ SUCCEEDED | FAILED | DENIED | CANCELLED | EXHAUSTED
```

The in-memory `RunEventChain` and schema-v3 SQLite authority share the same pure reducer. SQLite generates and replays durable events, enforces exact producer/outcome/subject/result bindings, consumes single-use decisions, and owns the authoritative budget/reservations. `PolicyEngine` remains the pure decision evaluator; its legacy `BudgetLedger` is not used by the typed broker execution path.

The Linux/WSL `repository.read` backend is documented separately in [Read-only repository broker](read-only-broker.md). Governed local/cloud adapter identities, signed trusted evidence, durable audit, and a network-denied Linux/WSL launcher are implemented. A cloud provider alias is an observable routing identity, not an immutable-weight revision. Cryptographic remote producer identity, endpoint-specific network allowlists, and Windows/macOS executable backends are not inferred from these controls.

The SQLite authority is documented in [Durable runtime store](durable-runtime-store.md) and owns the full implemented read-only run aggregate.

## Proof boundary

Current tests prove structural fail-closed behavior, sanitized errors, decision replay protection, event/state ordering, durable budgets, trusted snapshot/observation ingestion, direct-egress denial for the tested Linux/WSL launcher, pinned adapter semantics, and the Linux/WSL repository boundary. Live evidence proves one small local/cloud conformance probe, not general model correctness, provider privacy, Windows/macOS safety, remote non-repudiation, or production autonomy.
