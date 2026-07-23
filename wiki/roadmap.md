# Roadmap

**Updated:** 2026-07-23

| Milestone | Deliverable | Status |
|---|---|---|
| M0 | Inventory, research, threat hypotheses, baseline tasks | Complete enough to start; benchmarks remain open |
| M1 | Schemas, CLI, projections, audit, lock, tests | Implemented |
| M2 | Read-only PEP/broker, local+cloud adapters, sanitized run events | Complete for the embedded Linux/WSL reference profile; 187 tests plus passing live local/cloud evidence |
| M3 | Controlled writes, sandbox boundary, approvals, idempotency | Complete for bounded Linux/WSL one-file create/replace profile; 258 tests |
| M3.5 | Integration, reproducibility, governance reconciliation | Complete: `eco runtime doctor`, declared test extra, honest hosted-CI isolation scope, ADR-018 |
| M3.6 | Verification-only trust bootstrap | Complete: canonical external-trust policy and `eco runtime trust doctor`; consumed by M4 without self-signing |
| M4 | L0–L5 evaluation/promotion contract | Complete for fixed `wiki-health-check`: L0–L2 eligible after five attempts + replay; L3–L5 structurally ineligible |
| M4.5.1 | Safe project-adoption bootstrap | Complete: deterministic preview/apply, ownership receipt, reversible projections, adversarial uninstall, focused Linux/macOS/Windows CI |
| M4.5.2 | Platform and adapter capability profiles | Complete: closed non-authorizing profiles, passive doctor, six-platform fixtures and focused portability CI |
| M4.5.3 | Portable packaging and installer adapters | Complete for exact wheel-only offline integrity, preview-only adapters and real Linux private-venv install smoke |
| M4.6 | Controlled native backend conformance | Complete for fixed Linux/WSL namespace + Landlock observations; no runtime consumer |
| M5.0–M5.2 | Threat model, team identity contracts, externally anchored signed deny-all policy | Complete |
| M5.3 | Bounded exact RBAC/ABAC intersected with the existing PolicyEngine | Complete; narrowing-only and explicit-deny-first |
| M5.4 | Shared activation authority, revisions, snapshots and epochs | Complete for private same-host SQLite |
| M5.5 | Revocation, emergency recovery and dual-anchor generation rotation | Complete |
| M5.6 | Distinct-human quorum, separation of duties and single-use permits | Complete |
| M5.7 | CLI, backup, portability, documentation and release conformance | Complete for the bounded `0.7.0` profile |
| M6.0 | Functional-orchestration research, ADRs, contracts, threat model and acceptance gates | Complete |
| M6.1 | Governed model bridge plus fixed offline `source-review` vertical slice | Deterministic profile complete; enforcement chain exercised live, while a full live five-role model PASS remains an explicit nonclaim |
| M6.2 | Canonical skills and harness synchronization | Complete for the closed package-owned registry and six projection surfaces |
| M6.3 | Generic bounded loop engine | Complete for the embedded deterministic bounded-loop profile |
| M6.4 | Logical model roles, policy routing and explicit bounded fallback | Complete for exact policy/price/plan/Ed25519 authority, durable consumption and aggregate per-effect usage |
| M6.5 | Provenance-preserving private context and memory graph | Complete for CAS-bound embedded memory, TTL-safe reversible compaction and exact namespace retrieval |
| M6.6 | General workload-agent team orchestration | Complete for the embedded narrowed-delegation coordinator |
| M6.7 | Governed live research tools | Complete for bounded credential-free public search/fetch contracts and broker; provider quality remains unclaimed |
| M6.8 | Cross-platform contracts, conformance and `0.8.0` release | Implementation, local gates and independent audit complete; GitHub hosted matrix is externally blocked before job creation |
| M7 | Enterprise/network authority and native security backends | Re-sequenced from old M6; not dropped or claimed |
| GSC | Gated self-creation of skills/agents/loops under adversarial promotion gates | Proposed (design only); see [proposal](../docs/research/2026-07-22-gated-self-creation-contract-proposal-claude.md) |
| M8 | Optional training/learning and experimental nodes | Future; MOLT/local GPU are adapters, not dependencies |
| Product / Nordrassil | Normal-user workspace over the core | Active sibling product: gateway/chat foundation, blind Compare, local-model Cookbook and multi-project Files implemented; see [product page](nordrassil.md) |

## Product track — Nordrassil

Nordrassil is not a replacement for the canonical milestones above. It is the
user-facing consumer that makes their bounded capabilities usable. The current
product sequence is:

1. complete persistent Chat sessions and provenance-bound attachments;
2. add a provider/deployment registry with probes and conformance labels;
3. expose governed Research and versioned Documents;
4. expose bounded Agent runs, skill repair loops and evaluated teams;
5. add approved external connectors, then auth, backup and PWA hardening.

Product convenience cannot reinterpret an allow-candidate as final runtime
authority. The detailed current state, local-model inventory, Odysseus audit and
verification evidence are recorded in [Nordrassil](nordrassil.md).

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
8. All M2 regression and project gates pass: `unittest` plus the declared pytest extra, compile, validate, render, doctor and diff checks. Live namespace/Landlock conformance runs only on a capable Linux/WSL host; unsupported hosts report a skip, not a security pass.

This profile does not authorize delete, rename, directory creation, multi-file batches, arbitrary commands, A3/A4 actions, live-root promotion or non-Linux backends. See the [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md).

## M3.5 integration and reproducibility exit criteria

1. An installed `eco` command constructs the real embedded read-only runtime boundary without model egress, write authority, committed keys, or repository mutation.
2. The command reports a structured, sanitized readiness result and refuses execution until signed evidence and trust-key provisioning are configured.
3. The documented pytest gate is installable from project metadata and lockable from a clean environment.
4. Hosted CI distinguishes unit coverage from privileged Linux/WSL namespace/Landlock conformance; unavailable controls remain a visible non-claim.
5. The Phase-0 constitution has a dated canonical supersession decision and generated client projections agree with its retained universal guarantees.

See the [M3.5 report](../docs/research/2026-07-16-m3.5-integration-reproducibility-report.md) and [ADR-018](../docs/decisions/README.md#adr-018--reconcile-the-phase-0-constitution-with-canonical-authority-and-bounded-loops).

## M3.6 verification-only trust-bootstrap exit criteria

1. Canonical configuration declares verification references and exact evidence bindings without committing signing keys, evidence bodies, provider credentials, or runtime state.
2. The executable can verify only externally prepared canonical evidence and cannot self-sign a snapshot or conformance observation.
3. Missing, stale, malformed, changed, insecure, symlinked, or repository-resident evidence leaves execution blocked without raw-data leakage.
4. A successful trust doctor remains verification-only: no repository read, model request, network egress, store, artifact, run, approval, or write authority is created.

M4 consumes this verification through a separate no-model A1 plan/lifecycle; the model-routed RunPlan is not repurposed. See the [M3.6 report](../docs/research/2026-07-16-m3.6-verification-only-trust-bootstrap-report.md) and [ADR-019](../docs/decisions/README.md#adr-019--verification-only-external-trust-bootstrap).

## M4 exit criteria

1. A separate route-free no-model plan binds the exact signed three-entry D0/P1 scope and zero model/network/write budgets.
2. Every broker read requires fresh expiring single-use policy authority; forged, drifted, expired, repeated, or out-of-scope authority fails closed.
3. Private external HMAC state contains no raw path/content, rejects unsafe SQLite/link/permission/concurrent-owner topology, and replays terminal success without rereading.
4. The fixed report verifies signed bytes, one primary heading per document, and distinct documents without repository mutation.
5. Five independent attempts must agree exactly; completed observations survive recovery, ambiguous post-start reads fail without retry, terminal recovery must replay with zero reads, and any safety violation blocks promotion.
6. Passing grants only L0–L2. L3–L5, scheduling, autonomous retry, model, network, and writes remain ineligible.
7. Complete M1–M3 regression plus CLI/schema/compile/projection gates pass.

All criteria pass for the embedded Linux/WSL reference profile. See the [M4 report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md), [architecture](../docs/architecture/no-model-wiki-health.md), and [ADR-020](../docs/decisions/README.md#adr-020--separate-no-model-a1-lifecycle-and-fixed-l0-l2-promotion-gate).

## M4.5.1 exit criteria

1. `eco adopt --dry-run` is deterministic, content-minimized, schema-valid, and zero-write.
2. Apply is serialized and requires the exact recomputed preview digest.
3. Fresh, explicit existing-config, and reinstall modes preserve distinct ownership.
4. Existing instruction bytes, including CRLF and missing final newlines, are exactly restorable.
5. Path escape, symlink, hardlink, non-UTF-8, stale plan, invalid state, forged marker, and backup tampering fail closed.
6. Catchable partial failure rolls back ecosystem-written bytes only; a concurrent user edit is preserved and reported as a conflict.
7. Full removal completes a zero-write preflight and refuses canonical/projection drift, unknown `.ai` entries, pre-existing canonical files, or missing ownership evidence.
8. Complete Linux regression and focused Linux/macOS/Windows adoption gates pass.
9. Documentation and wiki state the portability proof without implying cross-platform runtime security.

All criteria pass for the bounded filesystem bootstrap. It has no durable crash journal and makes no hostile concurrent-parent-swap, reparse/case-fold, packaging, or non-Linux runtime-backend claim. See the [architecture](../docs/architecture/project-adoption.md), [completion report](../docs/research/2026-07-16-m4.5.1-adoption-bootstrap-report.md), and [ADR-021](../docs/decisions/README.md#adr-021--preview-bound-receipt-owned-project-adoption).

## M4.5.2 exit criteria

1. Define `PlatformProfile` and `AdapterCapabilityProfile` JSON Schemas.
2. Separate operator declaration, read-only detection, and conformance-proven capability state.
3. Implement sanitized `eco platform doctor --json` with no installation or authority side effect.
4. Add Windows-native, macOS, Linux, WSL, container, and hosted-CI fixture profiles.
5. Report executable/client inventory categorically while filesystem security, environment-reference, shell/process and active adapter semantics remain explicit `not-tested` until independently proven.
6. Keep read broker, isolation, controlled writes, credentials, model routing, and loops unavailable whenever their backend-specific conformance is absent.
7. Freeze packaging requirements only after the capability contract survives adversarial review.

All criteria pass for the passive description boundary. The doctor never accepts unsigned proof, and both profile contracts structurally forbid proven/effective runtime state. Six fixtures cover Linux, WSL, macOS, Windows, container, and hosted CI; hosted cross-OS jobs prove portable contract behavior, not native runtime-security backends. See the [architecture](../docs/architecture/platform-adapter-conformance.md), [completion report](../docs/research/2026-07-16-m4.5.2-platform-adapter-conformance-report.md), and [ADR-022](../docs/decisions/README.md#adr-022--passive-platform-and-adapter-description-cannot-mint-runtime-proof).

## M4.5.3 exit criteria

1. A closed deterministic manifest binds the main wheel, every dependency wheel, lock, source revision and packaged schema inventory.
2. Installed and standard-library verifiers are offline/read-only and reject malformed manifests, byte tampering, missing/extra artifacts, unsafe aliases and invalid wheel/archive structure.
3. Main/dependency fixtures are structurally valid wheels; the hosted gate builds and verifies the real distribution rather than trusting filenames.
4. Package-manager adapters are argv previews with `executionReady: false`; detection cannot select an installer or create runtime proof.
5. The Linux reference gate installs a verified complete wheelhouse into a clean private virtual environment with no package index and runs the installed `eco 0.6.0`.
6. Python package lifecycle remains separate from M4.5.1 repository adoption ownership/removal.
7. The support matrix states that publisher authentication, CAS handoff, manager rollback transactions, zipapp/standalone and OS-native packages are not implemented.

All criteria pass for the bounded integrity profile. See [architecture](../docs/architecture/portable-distribution.md), [completion report](../docs/research/2026-07-16-m4-portability-completion-report.md), and [ADR-023](../docs/decisions/README.md#adr-023--distribution-integrity-package-installation-and-project-adoption-are-separate-boundaries).

## M4.6 exit criteria

1. Passive `platform doctor` remains zero-process/zero-network/zero-write; active execution is a separate explicit command requiring confirmation and exact suite inputs.
2. The runner accepts only a fixed packaged synthetic suite, private empty external root and exact platform/distribution/backend bindings.
3. The Linux/WSL suite proves only clean environment, Landlock workdir boundary, namespace network denial, output/deadline bounds, read-only workdir and closed stdin.
4. A closed `PlatformBackendConformanceProfile` contains no raw path, canary, output, port, PID, host/user or exception data and uses observations, never effective capabilities.
5. Failed/unsupported/partial suites expose no observations. Windows/macOS/container/hosted-CI are explicit negative profiles.
6. External envelope ingestion re-verifies issuer, freshness, suite, platform, distribution, backend-instance, backend-implementation and runner bindings but has no policy/runtime consumer.
7. Adversarial schema/zero-effect/fake-backend/signing/replay tests, existing isolation tests and a real local WSL suite pass.

All criteria pass for the bounded Linux/WSL backend observation profile. See [architecture](../docs/architecture/platform-backend-conformance.md), [completion report](../docs/research/2026-07-16-m4-portability-completion-report.md), and [ADR-024](../docs/decisions/README.md#adr-024--active-backend-conformance-produces-observation-never-effective-authority).

## M5 exit criteria

1. Team, principal, membership, public-key and policy-bundle records use a separate closed authority namespace.
2. Record and cross-record digests are deterministic, non-self-referential and exact.
3. A policy signature is verified only relative to a caller-supplied external immutable Ed25519 anchor; an embedded key cannot bootstrap trust and anchor provenance is not claimed.
4. Signed access rules use exact action/resource matching, deny precedence and can only narrow a trusted current `PolicyEngine` decision.
5. Currentness is established only by private authenticated SQLite activation with monotonic revision, predecessor digest, snapshot CAS and serialized writers.
6. Runtime identity is derived from current signed state; live HMAC, raw envelope, signature, epoch and revocation checks fail closed.
7. A2 permits require an exact signed profile/request, distinct eligible human principals, requester separation, current epochs and authority-ledger issue/consumption.
8. Emergency deny blocks authorization and effects; disable requires an exact signed recovery profile and at least two independent human approvals in one transaction.
9. Trust-anchor rotation requires old and new signatures and creates a successor authority generation without rewriting the predecessor.
10. CLI activation/doctor, coherent verified backup, reopen/tamper checks, cross-platform contract tests and `0.7.0` metadata are delivered.
11. M4 schema digest, existing runtime behavior and all earlier tests remain unchanged.

All criteria pass for the bounded same-host reference profile. PostgreSQL/network authority, SSO/OIDC/WebAuthn, KMS/HSM/Vault, HA/consensus, multi-region operation, native Windows ACL enforcement, native macOS/Windows runtime backends and A3/A4 remain M6. See [team authority](../docs/architecture/team-authority.md), [completion report](../docs/research/2026-07-16-m5-team-authority-completion-report.md), [operations runbook](../docs/operations/team-authority-runbook.md), [ADR-025](../docs/decisions/README.md#adr-025--signed-team-declarations-authenticate-bytes-but-do-not-create-authority), and [ADR-026](../docs/decisions/README.md#adr-026--team-authority-is-a-narrowing-same-host-authority-with-generation-based-rotation).

The final sentence above describes the roadmap as it stood at M5 completion. ADR-027
re-sequences that enterprise/native backlog to M7; it does not change the M5 proof
boundary.

## M6.0 exit criteria

1. Record why useful functional orchestration precedes the old enterprise M6
   backlog without weakening M1–M5.
2. Define a separate `orchestration.ai.ecosystem/v1alpha1` registry and keep the
   existing runtime schema digest unchanged.
3. Freeze the fixed offline `source-review` roles, DAG, source limits, typed-channel
   boundary, budgets, revision rule, terminal meanings and explicit non-goals.
4. Define the governed durable model-invocation bridge that must exist before a
   team runner may call an adapter.
5. Record threat boundaries and adversarial gates for source injection, routing,
   budgets, reviewer separation, crash recovery, isolation and redaction.
6. Register the user-supplied multi-model article and exact OpenResearcher,
   OpenScience and MOLT snapshots as reviewed untrusted sources.
7. Preserve the 474-test M1–M5 baseline and canonical validation/projection gates.

M6.0 documentation is not M6.1 implementation evidence. See the
[architecture](../docs/architecture/functional-orchestration.md),
[threat model](../docs/architecture/m6-functional-orchestration-threat-model.md),
[research plan](../docs/research/2026-07-17-m6.0-functional-orchestration-plan.md),
[ADR-027](../docs/decisions/README.md#adr-027--prioritize-functional-orchestration-before-enterprise-backends)
and [ADR-028](../docs/decisions/README.md#adr-028--add-an-orchestration-plane-without-reinterpreting-runtime-authority).

## M6.1 exit criteria

1. Every workflow model call traverses exact active-plan policy authorization,
   durable PREPARE/start fencing, broker-owned adapter invocation, private CAS and
   atomic result/accounting settlement.
2. Pre-start recovery is safe; post-start ambiguity never triggers automatic retry;
   terminal replay makes zero provider calls.
3. SourceBundle ingestion is bounded, path-safe, digest/length exact, UTF-8-only for
   the initial profile and never executes source code.
4. Planner → analyst → verifier → synthesizer → reviewer runs as an exact sequential
   DAG with typed handoffs, one possible synthesis/review revision and at most seven
   calls.
5. Claims, source locators, verification and reviewer records form an exact graph;
   unsupported or conflicting claims remain visible and can force `incomplete`.
6. The hard gate, not a model, owns terminal status; `incomplete`, `denied`,
   `exhausted`, `failed` and `cancelled` are never reported as success.
7. Source network, tools and workspace writes remain zero. Agent credentials and
   direct egress remain absent.
8. Full regression, adversarial, leak, crash, installed-wheel and repository-identity
   gates pass with exact non-claims.

M6.1 is deliberately a zero-cost `local-loopback` profile. It does not accept
caller-asserted provider prices: cloud pricing, multi-model routing and fallback
policy belong to M6.4.

## M6.2 exit criteria

1. A closed package-owned registry binds id/version, source revision, content
   digest, license, owner, capabilities, dependencies, tests, evidence,
   revocation and per-surface compatibility for every skill.
2. Three dogfood skills cover ecosystem contract changes, bounded loop authoring
   and source-review evidence discipline without granting authority.
3. `eco skills plan|sync|check|uninstall` is deterministic, never executes skill
   code, preserves unmanaged bytes and binds projections to an ownership lock.
4. Codex, Claude, Gemini and generic portable outputs are separate;
   Copilot/Cursor are explicitly instruction-only.
5. Traversal, case/Unicode aliases, symlink, hardlink, forged ownership, drift,
   redirected lock, partial sync and partial uninstall fail closed or roll back.

See [skills and harness synchronization](../docs/architecture/skills-harness-sync.md).
External imports, signature/transparency verification, live-client semantic
conformance and skill execution are not part of M6.2.

## M6.3–M6.7 exit evidence

1. M6.3 provides a closed loop-definition/instance/transition contract,
   deterministic state machine, explicit retry/hard-stop budgets, crash recovery
   and separate evaluation; it is not a background scheduler.
2. M6.4 derives routes only from validated policy, observations, exact deployment
   identity and price catalog. `source-review` additionally requires a signed
   execution-plan binding and atomically consumes both the route and each
   worst-case provider-effect reservation before egress.
3. M6.5 keeps content in private CAS, authenticates digest-only provenance,
   applies namespace/class/TTL/query budgets, preserves conflicts and prevents a
   compacted summary from outliving its earliest transitive source.
4. M6.6 executes exact task DAGs with narrowed child authority, serialized claims,
   aggregate budgets, typed handoffs, cancellation and truthful partial failure;
   scheduling does not authorize effects.
5. M6.7 permits only policy-bound credential-free public HTTPS search/fetch with
   exact domain, redirect, media, size, time, data and retention limits. Retrieved
   content remains untrusted CAS data.

See the corresponding architecture pages for the exact contract and nonclaim of
each slice.

## M6.8 exit criteria

1. Preserve the complete M1–M6 regression on Python 3.11 and 3.12 under the
   frozen dependency lock.
2. Run the full filesystem/runtime suite on Linux and focused pure
   contract/sync/portability suites on Windows and macOS; no cross-OS runtime
   security inference is permitted.
3. Keep canonical `validate`, `render --check`, `doctor`, `skills check`, compile
   and whitespace gates green.
4. Preserve the pinned runtime schema digest while publishing exact additive
   orchestration/routing/memory/team/research digests.
5. Build a locked wheelhouse, verify its distribution manifest, install it with
   `--no-index`, import every M6 package/resource and run a deterministic
   five-role literal-loopback smoke from the installed environment.
6. Verify repository bytes and mtimes remain unchanged after the smoke and scan
   public/control-plane/journal surfaces for unique private sentinels.
7. Require independent review and close all P0 exact-route findings before the
   `0.8.0` claim.
8. Separate deterministic scripted evidence from live-provider observations.

The adapter observation envelope remains a local HMAC shared-key integrity
profile: it does not cryptographically separate signer and verifier. Route
authority does use external Ed25519 verification. Local journals are not a
rollback-resistant external transparency service if an operator deletes the
entire state authority. Native Windows/macOS enforcement, arbitrary providers,
model truth, prompt-injection immunity and a full live five-role PASS remain
explicit nonclaims.

## Loop rollout

| Phase | Allowed loop behavior | Dependency |
|---|---|---|
| Current / M1 | Manual commands and documented candidates | Existing compiler and validation |
| M2 | L2 observe/report-only loop prototype | Read-only PEP, sanitized events, negative bypass tests |
| M3 | L3 proposals and narrowly approved L4 writes | Implemented primitive: exact approval, idempotency, CAS rollback and restart recovery |
| M4 | Fixed no-model L0–L2 promotion | Implemented five-attempt quality/safety/stability gate plus recovery replay; L3–L5 denied |
| M6.1 | Manual exact-routed five-role source review | Implemented; deterministic gate owns success and all effects cross durable authority |
| M6.3 | Reusable embedded bounded loops | Implemented library; no daemon, autonomous scheduler or implicit promotion |

The first reference loop remains `wiki-health-check` in manual L2 observe-only
mode; `source-review` is the first governed model-backed team workflow.
`ml-autoresearch` follows only after experiment isolation, immutable evaluation,
reproducibility and approved local-compute resource limits are enforced. A DGX is
one optional local profile, not a dependency. See [Loop engineering](loops.md).

## Sources

- [Architecture](../docs/architecture/README.md)
- [Decision register](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [M4 no-model wiki health](../docs/architecture/no-model-wiki-health.md)
- [M4 completion report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md)
