# Agents — optional role patterns

Agent roles are reusable workflow patterns, not mandatory runtime services and not model aliases.

| Role | Purpose | Required evidence |
|---|---|---|
| Planner | Decompose a bounded task | Plan schema and termination criteria |
| Implementer | Produce a code/document artifact | Deterministic tests or acceptance artifact |
| Reviewer | Independently check a completed artifact | Findings tied to exact files/claims |
| Security reviewer | Attempt policy or trust-boundary failure | Negative tests and reproducible evidence |

Rules:

- Single agent is the baseline.
- Add another role only if evaluation shows incremental benefit.
- Handoffs are typed artifacts with provenance and narrowed permissions.
- Credentials are never delegated through a handoff.
- A reviewer must be independent for high-risk work; deterministic gates may be sufficient for low-risk mechanical work.
- Role names never imply a model vendor or fixed deployment.

Future role contracts belong under `.ai/agents/` after a schema and conformance test exist.
