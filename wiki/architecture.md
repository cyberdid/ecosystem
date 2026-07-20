# Current architecture

**Updated:** 2026-07-20
**Status:** bounded M1–M6.8 implemented and locally gated; hosted `0.8.0` jobs are externally blocked before creation

## TL;DR

The repository implements canonical contracts/compiler plus an embedded default-deny runtime, governed model adapters, durable Linux/WSL reads and exact-approved one-file writes, one fixed no-model loop promoted only through L2, safe project adoption, platform/distribution conformance, and a portable signed team-authority layer. M5 adds exact narrowing team access, private same-host activation/currentness, revocation, emergency recovery, dual-signed rotation and distinct-human quorum permits. M6 now turns that foundation toward useful skills, loops, model roles, memory and agent teams without depending on one laptop, GPU, model or client.

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
→ deterministic adoption preview + ownership receipt + reversible uninstall
→ passive platform doctor + declaration/inventory-only profiles
→ exact offline wheelhouse/lock/schema verifier + installer previews
→ explicit fixed Linux/WSL backend suite + externally signable observation
→ externally anchored signed team identity and access policy
→ private authenticated SQLite activation/revocation authority
→ distinct-human approval quorum + single-use action permits
→ emergency recovery + dual-signed successor-generation rotation
→ governed typed five-role source-review
→ deterministic skills projections + bounded loop engine
→ exact Ed25519-authenticated routing + durable aggregate effect usage
→ private provenance memory + narrowed durable workload-agent teams
→ governed credential-free public research broker
```

## Explicitly not implemented

- endpoint-specific network allowlist backend;
- Windows/macOS executable broker and isolation backends;
- Windows/macOS controlled-write backends;
- autonomous model-selected routing;
- durable replay registry for evidence envelopes;
- asymmetric evidence signatures;
- cryptographic remote issuer identity;
- enterprise WebAuthn/OIDC/SSO identity and approval service;
- caller-independent KMS/HSM/Vault anchor and secret custody;
- full-wiki link/staleness lint, scheduler, autonomous retry, and L3–L5 loop authority.
- durable adoption crash journal and hostile filesystem-race proof;
- publisher-authenticated releases, immutable installer CAS handoff and transactional multi-manager rollback;
- native Windows/macOS backend runners and runtime consumption of backend observations.
- PostgreSQL/network authority, HA/consensus and multi-region recovery;
- A3/A4 action profiles and remote transactional effect adapters.
- rollback-resistant external anchoring for deletion/replacement of complete local
  route/runtime state;
- model truth, prompt-injection immunity, provider equivalence or a complete live
  five-role PASS;

The implemented M2–M4 boundary has negative, concurrency, process-crash, artifact, migration, backup, key-rotation, anchor, adapter, isolation, evidence, parity, exact-approval, CAS-recovery, no-model replay, state-integrity, repository-nonmutation, and promotion tests. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md), [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md), and [M4 report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md).

## Current M4 vertical slice

`eco run wiki-health-check` manually verifies exactly three externally signed D0/P1 wiki pages with zero model/network/write budget. Each broker attempt has a durable `started` ambiguity fence; only pre-start recovery may reauthorize, while an uncertain post-start outcome fails without rereading. The deadline survives recovery and policy freshness advances during the run. `eco eval wiki-health-check` requires five stable independent journals and a zero-read replay, then marks only L0–L2 eligible. Reports/journals contain no raw path or content. See [M4 no-model wiki health](../docs/architecture/no-model-wiki-health.md).

## Current M4.5.1 adoption slice

`eco adopt --dry-run --json` produces a schema-valid content-minimized plan with relative paths, operation classes, digests, discovery counts, and sanitized blockers. `eco adopt --apply PLAN_SHA256` locks, recomputes, validates, preserves existing instruction bytes, and writes `.ai/adoption.json`. Fresh, pre-existing config, and reinstall ownership are distinct. Clean reinstall is a byte/mtime no-op. Full removal requires strict render state and verified backup digest/size, refuses drift/unknown/pre-existing config before mutation, and never trusts marker text alone.

Focused adoption tests run on hosted Linux, macOS, and Windows. This does not port the M2–M4 security backends. See [safe project adoption](../docs/architecture/project-adoption.md).

## Current M4.5.2 platform/adapter slice

`eco platform doctor --json` emits only coarse OS/context, allowlisted executable-name, fixed client-surface, and explicit `not-tested` semantic state. It does not invoke tools, contact adapters, read projection content, resolve credentials, mutate the repository, or create authority. `PlatformProfile` and `AdapterCapabilityProfile` are closed, digest-bound, and structurally forbid proven/effective state; existing signed runtime `AdapterConformanceProfile` remains the proof boundary. Six fixtures cover Linux, WSL, macOS, Windows, container, and hosted CI, while nested contexts and mutable-hint spoofing fail closed.

## Current M4.5.3/M4.6 portability slices

`DistributionManifest` binds a real main wheel, every dependency wheel, `uv.lock`, source revision and schema inventory. Installed and standard-library verifiers stay offline/read-only; manager adapters are preview-only, while Linux CI performs a real clean offline virtual-environment install. The manifest explicitly does not attest publisher origin, and package installation never mutates project adoption state.

`eco conformance run` is separate from passive doctor and accepts only the fixed namespace/Landlock suite in a private external root. Its content-free `PlatformBackendConformanceProfile` records narrow observations bound to platform, distribution, backend instance/implementation, runner and suite. External signing/ingestion is supported, but M4.6 has no policy/runtime consumer. Windows, macOS, container and hosted-CI profiles remain unsupported negatives. See [portable distribution](../docs/architecture/portable-distribution.md) and [backend conformance](../docs/architecture/platform-backend-conformance.md).

## Current M5 team-authority slice

Externally anchored Ed25519 bundles define exact team identities, memberships, public keys, access rules and approval profiles. A private HMAC-authenticated SQLite store establishes monotonic currentness, snapshots, revocation/emergency epochs, permit consumption and immutable audit evidence. Catalog labels alone are not actor authentication: runtime and recovery requests require an exact short-lived Ed25519 `workload-authentication` assertion. Team access is only a narrowing candidate; repository read/write effects additionally require an exact ToolRequest-bound, single-use PolicyEngine claim, optionally persisted in the runtime SQLite store. A2 uses distinct eligible human principals, authenticated requester separation and an authority-issued single-use permit; emergency disable requires a separate recovery quorum. Old+new dual-signed rotation creates a successor generation rather than rewriting history.

Contract behavior is tested on Linux/macOS/Windows; strong private-permission enforcement is POSIX-bounded. Scheduling, autonomous retry, full-wiki lint, publisher provenance, enterprise/network authority, native cross-platform runtime-security backends and every A3/A4 or L3–L5 profile remain separate future gates. See [M5 team authority](../docs/architecture/team-authority.md) and the [completion report](../docs/research/2026-07-16-m5-team-authority-completion-report.md).

## Current M6 functional-orchestration implementation

M6 is re-sequenced from enterprise infrastructure to Universal Functional
Orchestration. The old PostgreSQL/SSO/KMS/HA/native-backend backlog becomes M7.
This changes priority, not authority.

The additive `orchestration.ai.ecosystem/v1alpha1` plane defines roles, team and
loop manifests, SourceBundle, parent team plans, route decisions, role attempts,
typed handoffs, claim/evidence/verification/review records, terminal results and
content-free events. The existing runtime schema digest is deliberately unchanged.

M6.1 begins with a durable policy-authorized model bridge, because calling the
current adapter directly would bypass persistent model budgets and crash/replay
semantics. Its first user-facing workflow is the fixed offline sequence planner →
analyst → verifier → synthesizer → reviewer, with one possible revision, at most
seven calls, one explicit deployment pin, P0 outputs and zero source-network,
tools or workspace writes.

The production composition is reachable as `eco team run source-review`;
`--check` performs zero-write/zero-egress preflight.
It accepts only one enabled local OpenAI-compatible deployment, exact signed
structured-output evidence, a literal loopback endpoint, a strict path-bearing
manifest and private external SQLite/CAS state. Every role dynamically creates
an exact child runtime plan and model decision, then crosses durable model
PREPARE/STARTED/terminal fencing through the typed adapter. Reusing the exact
run/store/time/state tuple replays terminal outputs from CAS with no duplicate
provider call. An exact five-file M6.4 route is mandatory: Ed25519 authority
binds the policy, price catalog, request, decision and secret-free execution
plan; each provider effect re-verifies it and atomically reserves aggregate
usage before egress. Output is limited to the content-free result graph and
report artifact binding.

This is a bounded local zero-cost profile, not a claim of general multi-model
routing, provider pricing, source-network research, tool use, prompt-injection
immunity, universal factual truth, arbitrary-duration recovery or live model
quality. Deterministic installed-wheel and hosted release gates remain separate
until M6.8 evidence is recorded.

See [functional orchestration](../docs/architecture/functional-orchestration.md),
the [threat model](../docs/architecture/m6-functional-orchestration-threat-model.md),
the [M6.0 plan](../docs/research/2026-07-17-m6.0-functional-orchestration-plan.md)
and the [roadmap](roadmap.md).

## Current M6.4 logical routing implementation

The additive `routing.ai.ecosystem/v1alpha1` package defines five provider-neutral
workload roles and makes routing a pure digest-bound decision over role, action,
data class, zone, retention, context, observed capabilities, trusted price
snapshot, deadline and cost ceiling. No eligible deployment produces a typed
denial. Explanations expose only digests and fixed reason codes, never source,
prompt, endpoint, secret or raw evidence data.

Fallback is a fresh second decision only for explicitly allowed `capacity` or
`transport-retryable` failures. Policy, privacy, authority, schema, ambiguous,
identity-drift, deadline and budget failures never switch providers. The old
candidate is excluded and every current condition is evaluated again. The
M6.1 local profile remains local-only with a calculated zero-cost reservation.

The pure router still does not invoke a model or claim current provider prices or
performance. Composition adds separate Ed25519 authority, an authenticated
single-use consumption journal and an atomic per-effect aggregate usage journal;
none of them replaces the existing runtime model authorization. See
[M6.4 logical model routing](../docs/architecture/model-role-routing.md).

## Current M6.5 private context-memory slice

The additive `memory.ai.ecosystem/v1alpha1` package stores facts, claims,
decisions, constraints, open questions, failed approaches and summaries as sealed
metadata bound to exact private-CAS artifacts. Its private SQLite index contains no
raw body, authenticates every record and append-chain entry, rejects forged or
cross-project/team/run links and treats memory only as context.

Retrieval requires exact namespace, data class, P-level, TTL and a trusted caller-
owned read policy. Item, byte and deterministic token-estimate budgets are hard;
ordering is timestamp plus digest, not an unearned semantic score. Refutation and
conflict components are atomic under truncation. Compaction adds a reversible
summary with the complete source/artifact/relation graph and cannot hide a
conflict or delete the source records.

This is an embedded same-host library, not vector/semantic search, distributed
memory, encryption/KMS, automatic truth promotion, autonomous learning or a new
authority source. See [M6.5 private context and memory](../docs/architecture/private-context-memory.md).

## Current M6.6 general agent-team slice

The additive `teams.ai.ecosystem/v1alpha1` plane seals an exact M5-bound team
manifest, tasks, typed handoffs and truthful terminal results. A private embedded
SQLite coordinator serializes task claims, reserves aggregate budget ceilings,
propagates cancellation and distinguishes safe pre-effect lease recovery from
post-start ambiguity. Its full mutable state and append chain are caller-key HMAC
authenticated in a private external path; a trusted internal clock, not a worker
timestamp, governs expiry. Children can only narrow their parent's already bounded
role/action/data/tool/zone/time/budget envelope.

M5 current identity/access and a separate opaque runtime authorization are both
rechecked at effect start. An M6.4 route is consumed once but grants nothing by
itself; the full current route/request, trusted policy/price bindings, selected
deployment and exact `ModelRequest` are revalidated atomically. `model.invoke`
binds the exact `ModelRequest` runtime subject to its
deployment identity and input data class instead of applying repository-resource
equality. This is a single-host API, not a distributed scheduler or provider-
independence claim. See [M6.6 general agent teams](../docs/architecture/general-agent-teams.md).

## Current M6.7 governed research implementation

The separate `research.ai.ecosystem/v1alpha1` plane binds public search/fetch to
exact policy, capability, request and artifact records. Broker-owned transport
allows only credential-free public HTTPS under explicit domain, redirect, media,
wire/decoded size, deadline, data-class, egress and retention limits. Retrieved
bytes enter private CAS with content-free provenance and remain untrusted input;
browser sessions, cookies and authenticated arbitrary endpoints are excluded.
See [M6.7 governed research tools](../docs/architecture/governed-research-tools.md).

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Safe project adoption](../docs/architecture/project-adoption.md)
- [Platform and adapter conformance](../docs/architecture/platform-adapter-conformance.md)
- [Portable distribution](../docs/architecture/portable-distribution.md)
- [Platform backend conformance](../docs/architecture/platform-backend-conformance.md)
- [M5 team authority](../docs/architecture/team-authority.md)
- [M5 operations runbook](../docs/operations/team-authority-runbook.md)
- [M6 functional orchestration](../docs/architecture/functional-orchestration.md)
- [M6.2 skills and harness synchronization](../docs/architecture/skills-harness-sync.md)
- [M6.5 private context and memory](../docs/architecture/private-context-memory.md)
- [M6 threat model](../docs/architecture/m6-functional-orchestration-threat-model.md)
- [Roadmap](roadmap.md)
