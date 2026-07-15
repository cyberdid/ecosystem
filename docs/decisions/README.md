# Architecture decision register

| ID | Decision | Status |
|---|---|---|
| ADR-001 | Contracts-first, adapters outside the stable core | Accepted |
| ADR-002 | Embedded-first physical topology | Accepted |
| ADR-003 | Vendor instruction files are projections | Accepted |
| ADR-004 | API compatibility is not capability compatibility | Accepted |
| ADR-005 | Runtime policy is outside prompts | Implemented for the embedded M2 read-only profile |
| ADR-006 | Single-agent default | Accepted |
| ADR-007 | DGX Spark is a deployment/evaluation profile | Superseded as an M2 dependency by ADR-016; retained as historical context |
| ADR-008 | Central service/A2A/Temporal/Kubernetes deferred | Accepted |
| ADR-009 | Runtime records are separate, immutable policy-bound contracts | Accepted |
| ADR-010 | Repository reads require a plan-bound classified snapshot and OS-specific broker | Accepted for Linux/WSL slice |
| ADR-011 | Durable runtime state uses a transactional safe-record journal; raw content never enters it | Implemented for the schema-v3 embedded authority |
| ADR-012 | Repository operations use two-phase accounting, fenced leases, opaque path references, and fail-closed recovery | Accepted for M2.5 store slice |
| ADR-013 | Runtime snapshots and observations require authenticated ingestion | Accepted for M2 |
| ADR-014 | Untrusted processes are network-denied; provider credentials belong to trusted transports | Accepted for Linux/WSL M2 profile |
| ADR-015 | Deployment promotion requires identical signed cross-deployment evaluation evidence | Accepted for M2 |
| ADR-016 | Hardware-neutral local/cloud substitution and observable cloud identity | Accepted; supersedes ADR-007 as the active deployment rule |

## ADR-001 — Contracts-first

The project owns schemas, project intent, capability vocabulary, projection ownership, run/artifact semantics, and evaluation criteria. It does not own foundation models or inference engines.

## ADR-002 — Embedded-first

The first useful product must run as a local CLI without a daemon, gateway, Kubernetes, or control service. Team services require measured shared-state or governance needs.

## ADR-003 — Projections

`.ai/instructions.yaml` is canonical. Client-specific instruction files are generated into native locations with ownership markers, drift detection, backups, and uninstall.

## ADR-004 — Capabilities

An OpenAI-compatible endpoint is a transport adapter. Exact tool calling, structured output, streaming, and other features must be declared and then observed for a governed deployment identity. Where a provider exposes only a moving alias, the observation is alias-bound and must not be described as immutable-weight revision evidence.

## ADR-005 — Policy boundary

Prompts and generated instructions are not authorization. Future model/tool credentials belong to a broker; unknown egress defaults to deny.

## ADR-006 — Multi-agent

One agent with a strong harness is the baseline. Review/security specialists are added only where task-specific evaluation shows net benefit after cost and failure accounting.

## ADR-007 — DGX

DGX Spark hosts optional local deployments and evaluations. Its loss may reduce local capacity but cannot destroy manifests, policy metadata, or audit records.

## ADR-008 — Deferred components

A2A, Temporal, Kubernetes, Vault, SPIFFE, and a multi-tenant control service remain optional. Each needs a trigger condition and can remain absent permanently in a personal deployment.

## ADR-009 — Runtime contracts and immutable policy binding

Canonical `ai.ecosystem/v1alpha1` YAML describes project intent. Per-run records use the separate `runtime.ai.ecosystem/v1alpha1` namespace and remain runtime state.

Every run must produce an immutable `RunPlan` binding the request, semantic configuration snapshot, exact deployment identity, observed capabilities, tool contracts, and budgets by digest. Tool and model authorization is single-use and bound to the complete request digest; parameter changes require a new decision.

M2 implements only allow/deny, A0/A1, inspect sandbox, network-denied untrusted execution, and no automatic fallback. Approvals and writes remain M3 work.

## ADR-010 — Snapshot-bound repository reads

A pathname allowlist or secret-name denylist is insufficient: symlinks, hardlinks, mutable content, and unknown data classification can violate the selected route. `repository.read` therefore requires a `RepositorySnapshot` bound into the immutable plan. Each readable path carries expected size, digest, data class, and trust; unknown, D4, higher-class, changed, linked, or non-regular content fails closed.

Filesystem safety is backend-specific. The current Linux/WSL backend uses `openat2` and has no portable fallback. Windows reparse safety and other filesystem profiles require separate implementations and conformance evidence.

## ADR-011 — Transactional safe-record journal

SQLite is the embedded M2.5 authority target for plans, decision nonces, events, budgets, operations, and artifact metadata. Security-sensitive updates use `BEGIN IMMEDIATE`; records are canonical and immutable; audit entries form an HMAC-authenticated chain. Raw prompt/tool/model content, credentials, environment, paths from tool requests, and provider bodies never enter the journal.

The current implementation additionally owns native durable events/replay, active-plan selection, absolute deadline, durable budget reservations, repository-read PREPARE/COMMIT, explicit no-retry recovery, artifact availability proof, terminal checkpoints, and exact result projection. The broker is filesystem-only and the typed orchestrator owns sequencing. An independently retained external anchor is still required to detect valid audit-tail truncation.

## ADR-012 — Two-phase repository operations and privacy-preserving recovery

A repository read crosses a database/filesystem boundary, so it cannot be one SQLite transaction. The runtime therefore commits authorization, decision consumption, tool spend, byte reservation, content-free intent, and a bounded lease before broker I/O. Success or failure is a second exact-bound transaction. Lease epochs fence stale workers; the current `no_retry` profile resolves an expired lease as failure instead of reclaiming it for another I/O attempt.

Raw paths are never persisted and are not represented by guessable plain hashes; the store uses a domain-separated HMAC under a stable key separate from the rotatable audit key. Consequently, the journal alone cannot reconstruct a request after restart. The implemented profile is explicitly `no_retry`: after lease expiry, exact-epoch resolution fails closed with a deterministic outcome, releases reserved bytes, and preserves the spent tool request. Any future retry profile requires a separately governed opaque/encrypted payload handle.

Opaque policy and broker capability objects are accepted only as single-process composition guards. Durable multiprocess authority requires signed issuance or an authenticated service boundary; this implementation does not claim otherwise.

## ADR-013 — Trusted runtime evidence is a typed boundary

Repository snapshots and adapter observations are authenticated canonical envelopes bound to issuer, key, record kind, project/deployment, suite, governed identity, and validity window. In production, `PolicyEngine` accepts canonical signed envelope bytes plus exact immutable `EvidenceIssuerPolicy` trust anchors, evaluation time, and expected project/root or deployment/suite/identity bindings. The engine constructs its own verifier and re-verifies the original envelopes at construction, run planning, plan activation, and tool authorization. Allow decisions expire no later than their supporting envelope/observation/snapshot evidence. There is no unsigned constructor or injectable verifier in the installed runtime package; deterministic fixture composition lives only under `tests/`.

## ADR-014 — Deny direct egress; isolate provider transport credentials

The Linux/WSL reference launcher is an untrusted-agent backend. It proves a clean environment, zero credential bindings, executable allowlisting, repository access restrictions, closed stdin, bounded output, and network denial before child execution. It rejects every credential binding and endpoint allowlist mode because that backend cannot safely host a credentialed transport. A provider transport is a separate trusted boundary and may own OS-managed authentication; untrusted agent/model processes do not receive provider credentials or direct egress.

Provider-owned transport and credential isolation do not make an unsigned observation trusted. Production policy authorization still requires the canonical signed evidence bytes and explicit trust context from ADR-013, and re-verifies those bytes at each authorization boundary.

## ADR-015 — Signed identical-suite evidence gates deployments

Transport compatibility is insufficient. One immutable suite is delivered through the same evaluation protocol to governed deployment identities at their strongest observable level. Narrowly normalized output and explicitly bounded usage are compared, observations are schema-validated, and a signed evidence envelope binds the complete comparison and observation inventory without raw prompt/output/provider bodies. The first live M2 proof covers local Ollama/Qwen and broker-owned Claude/Sonnet alias; it is a D0 conformance probe, not immutable cloud-weight attestation or a general quality-equivalence claim.

## ADR-016 — Substitute universal local/cloud profiles for a DGX dependency

**Date:** 2026-07-15

**Context.** ADR-007 treated DGX Spark as the intended local deployment/evaluation profile. The recorded DGX node later became unavailable. Keeping a branded machine as an M2 exit dependency would contradict the ecosystem's vendor-, model-, and topology-neutral purpose and would make an otherwise portable control plane depend on one retired host.

**Decision.** M2 and later promotion gates require one governed local deployment and one governed cloud deployment, not a DGX specifically. A DGX may return as an optional local compute profile after it passes the same contracts, isolation checks, and evaluation suite; it has no privileged architectural role.

Deployment identity is described at the strongest level that can actually be observed:

- local artifacts and executable transports may be bound to an exact manifest or executable digest when that digest is measured from the deployed artifact;
- a provider model alias such as `claude-sonnet-5` is an observable routing identity, not proof of immutable provider weights, tokenizer, serving stack, auxiliary models, or backend revision;
- a digest of an identity record proves that the record is unchanged; it does not upgrade an alias or caller-supplied value into independent provider attestation.

The first M2 live observations have a 24-hour validity window. After expiry they remain historical evidence that a dated probe ran, but they no longer authorize current capability routing. Continued promotion requires renewal with the same suite or an explicitly versioned successor, fresh identity observation, signature verification, and policy ingestion.

Retained evaluation artifacts are described as **raw-content-free D0 evidence**: they omit raw prompt and response bodies but retain metadata and deterministic digests. Plain SHA-256 output digests can reveal low-entropy values by guessing, so non-public evaluations require a keyed digest or a separately governed disclosure policy.

**Consequences.** ADR-007 remains in the register as provenance but no longer defines an active dependency. Roadmaps and architecture documents use “local/cloud” unless they discuss historical DGX material or an explicitly optional DGX profile. No cloud identity claim may imply immutable model weights without provider-verifiable revision evidence.

## Supersession

Decisions are not silently edited after implementation evidence contradicts them. Add a dated superseding decision with evidence, migration impact, and affected contract versions.
