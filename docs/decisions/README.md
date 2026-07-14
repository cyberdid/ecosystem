# Architecture decision register

| ID | Decision | Status |
|---|---|---|
| ADR-001 | Contracts-first, adapters outside the stable core | Accepted |
| ADR-002 | Embedded-first physical topology | Accepted |
| ADR-003 | Vendor instruction files are projections | Accepted |
| ADR-004 | API compatibility is not capability compatibility | Accepted |
| ADR-005 | Runtime policy is outside prompts | Accepted as design; implementation pending |
| ADR-006 | Single-agent default | Accepted |
| ADR-007 | DGX Spark is a deployment/evaluation profile | Accepted |
| ADR-008 | Central service/A2A/Temporal/Kubernetes deferred | Accepted |

## ADR-001 — Contracts-first

The project owns schemas, project intent, capability vocabulary, projection ownership, run/artifact semantics, and evaluation criteria. It does not own foundation models or inference engines.

## ADR-002 — Embedded-first

The first useful product must run as a local CLI without a daemon, gateway, Kubernetes, or control service. Team services require measured shared-state or governance needs.

## ADR-003 — Projections

`.ai/instructions.yaml` is canonical. Client-specific instruction files are generated into native locations with ownership markers, drift detection, backups, and uninstall.

## ADR-004 — Capabilities

An OpenAI-compatible endpoint is a transport adapter. Exact tool calling, structured output, streaming, and other features must be declared and then observed for a specific deployment revision.

## ADR-005 — Policy boundary

Prompts and generated instructions are not authorization. Future model/tool credentials belong to a broker; unknown egress defaults to deny.

## ADR-006 — Multi-agent

One agent with a strong harness is the baseline. Review/security specialists are added only where task-specific evaluation shows net benefit after cost and failure accounting.

## ADR-007 — DGX

DGX Spark hosts optional local deployments and evaluations. Its loss may reduce local capacity but cannot destroy manifests, policy metadata, or audit records.

## ADR-008 — Deferred components

A2A, Temporal, Kubernetes, Vault, SPIFFE, and a multi-tenant control service remain optional. Each needs a trigger condition and can remain absent permanently in a personal deployment.

## Supersession

Decisions are not silently edited after implementation evidence contradicts them. Add a dated superseding decision with evidence, migration impact, and affected contract versions.

