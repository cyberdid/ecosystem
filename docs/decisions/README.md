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
| ADR-017 | Controlled workspace writes use exact human approvals, a trusted CAS broker, and compare-and-swap rollback | Accepted for the M3 Linux/WSL single-file profile |
| ADR-018 | Reconcile the Phase-0 constitution with canonical authority, verified memory, and bounded-loop terminology | Accepted; supersedes the Phase-0 `AGENTS.md` as an authority source while preserving its universal guarantees |
| ADR-019 | Verification-only external trust bootstrap for live read-only workflows | Accepted for the embedded local-shared-key bridge; asymmetric external attestation remains a future profile |
| ADR-020 | Separate no-model A1 lifecycle and fixed L0–L2 promotion gate | Implemented for the Linux/WSL `wiki-health-check` reference profile; L3–L5 remain ineligible |
| ADR-021 | Preview-bound, receipt-owned project adoption | Implemented for the M4.5.1 `.ai` bootstrap; runtime-platform portability remains separate |
| ADR-022 | Passive platform/adapter description cannot mint runtime proof | Implemented for M4.5.2; active native conformance remains separate |
| ADR-023 | Distribution integrity, package installation and project adoption are separate boundaries | Implemented for the M4.5.3 wheel-only offline profile |
| ADR-024 | Active backend conformance produces observation, never effective authority | Implemented for the M4.6 Linux/WSL fixed suite; no runtime consumer |
| ADR-025 | Signed team declarations authenticate bytes but do not create authority | Implemented for the M5.0–M5.2 diagnostic foundation; activation and anchor provenance remain unavailable |

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

## ADR-017 — Exact approval and compare-and-swap controlled writes

**Date:** 2026-07-15

**Context.** M2 deliberately stops at A1 repository reads. Giving an agent a writable checkout, treating a prompt confirmation as authorization, or recording only a path allowlist would permit parameter substitution, approval replay, symlink and hardlink attacks, partial writes, and unsafe rollback after third-party edits.

**Decision.** The first M3 conformance profile is a deliberately narrow A2 operation: create or replace one bounded UTF-8 regular file below an already existing directory in an isolated Linux/WSL workspace. The untrusted agent produces candidate bytes in private scratch/CAS storage and never receives writable access to the governed workspace. A trusted write broker alone crosses that boundary.

Every operation binds, by canonical digest, the project/run/plan, policy allow decision, root identity and base snapshot, canonical target reference, exact expected-before state, desired artifact and size, display preview, limits, and rollback manifest. A separately configured human-approval authority signs that exact subject. Approval is expiring and single-use; changing any bound parameter requires a new proposal and approval. The runtime journal HMAC protects local journal integrity but is not evidence of human identity. The embedded HMAC approval verifier is a reference adapter whose configured key-to-human mapping must be replaced or backed by WebAuthn/OIDC or an equivalent authenticated approval boundary in multi-user deployments.

Before mutation, candidate bytes and the exact before-image (or an absence marker) must be durably available. The broker uses descriptor-anchored Linux resolution, rejects protected paths, symlinks, mount crossing, special files and multiple hard links, and rechecks compare-and-swap preconditions. The runtime store then holds a cross-connection active-plan transaction guard while the change authority persists a fenced `commit_ready` permit immediately before an atomic same-directory rename. Run termination cannot interleave with permit issuance. A stop or lease expiry after this one-shot permit does not retroactively revoke the kernel commit; ambiguous completion is reconciled and compensated from exact durable state. The broker fsyncs the file and parent directory, then verifies the installed digest. Rollback is also compare-and-swap: it restores the before-image only while the current file still equals the approved after-image. Unexpected state becomes `recovery_required`; it is never overwritten or reported as success.

The bounded M3 profile excludes delete, rename, directory creation, multi-file transactions, arbitrary command execution, live-root promotion, and A3/A4 external actions. Those capabilities require separate contracts and conformance evidence rather than silent broadening of this approval.

**Consequences.** M2's read-only store and regression profile remain valid. M3 uses a distinct write-authority journal so an old schema-v3 read journal is never implicitly migrated across a security-boundary change. The write journal contains only content-free records, opaque keyed path/CAS references, digests, authority state and an authenticated audit chain; raw paths, candidate bytes, backups, credentials and diffs remain outside SQLite. A private CAS recovery bundle is completed before mutation, allowing a restarted fenced worker to mark exact-before as failed or conservatively roll exact-after back; unrelated state remains `recovery_required`.

## ADR-018 — Reconcile the Phase-0 constitution with canonical authority and bounded loops

**Date:** 2026-07-16

**Context.** The Phase-0 `AGENTS.md` was the original human-readable constitution. It established valuable invariants: one source with many adapters, substitution through contracts, no capability claim without verification, persistent project memory, bounded loops, vendor neutrality, and secrets outside Git. M1 later made `.ai/instructions.yaml` canonical and turned `AGENTS.md` and the other client files into deterministic projections. That architectural change was implemented and tested, but the decision register did not explicitly supersede the original file as an authority source or state which guarantees survived.

The original document also mixed universal guarantees with one-machine assumptions and informal terminology. In particular, it named LiteLLM on `spark-ts:4000` as the model boundary, described backend replacement as a one-line change with no prompt changes, treated the presence of `STATE.md` as sufficient memory discipline, and used both `L0–L4` for ecosystem layers and colors for loop risk. Current loop documentation independently uses `L0–L5` for side-effect and maturity levels. Leaving both `L` taxonomies active makes statements such as “L3” ambiguous, while transport compatibility and a color label cannot establish semantic equivalence or authorization.

**Decision.** The Phase-0 `AGENTS.md` is superseded as a canonical authority source by `.ai/instructions.yaml`; it remains historical provenance in Git. The canonical graph preserves and strengthens its universal guarantees as follows:

- **one source, many adapters** is enforced by contracts-first editing, deterministic projections, drift checks, reversible adoption, and uninstall;
- **swap by contract** means an adapter may be replaced only when the target deployment satisfies the declared semantic capabilities and evaluation gates; replaceability is a measured migration property, not a guarantee of a one-line change;
- **no capability without verification** remains a mandatory rule and applies to models, tools, skills, loops, policies, recovery, and platform backends;
- **persistent state** may contain provenance-bound verified facts, general rules, open failures, and reviewed lessons. A project that uses the original five-section `STATE.md` convention may keep `Last session / Verified facts / General rules / Open failures / Lessons learned` as a human-readable projection, but the filename or presence of those headings does not make content trusted, grant permission, or replace a versioned state contract and gate;
- **bounded loops** require a trigger, bounded task, approved context, capability and policy decision, independent gate, state and evidence boundary, budgets, hard stops, audit trail, and separately authorized side effects. The original `automation + skill + state + gate + hard stop` formula remains a useful minimum mnemonic, not the complete enforcement contract;
- **vendor neutrality and secret hygiene** remain mandatory. No branded host, gateway, model alias, client, endpoint shape, MCP server, or skill format receives privileged authority merely because it is configured.

Effective instruction precedence is explicit: operator and platform policy first, then repository canonical contracts, then generated client projections, then task-local context. Lower-precedence material may narrow an action but cannot broaden authority. Runtime authorization remains outside every prompt and projection.

To remove the taxonomy collision, architecture discussions use **E0–E4** for the informational ecosystem stack:

- E0 — knowledge and verified project state;
- E1 — model/provider adapters and governed deployment identities;
- E2 — tools, skills, MCP adapters, and agent roles;
- E3 — methods, bounded loops, and evaluation workflows;
- E4 — client harness projections and user-facing integrations.

Loop documentation retains **L0–L5** exclusively for loop side-effect/maturity (`Manual` through `Evidence-compounding`). Green/yellow/red labels are operator-facing summaries only; D/A/Z/P classification and the policy boundary determine authority.

The machine-specific LiteLLM/DGX endpoint, exact role aliases, and the claim that any backend replacement needs only one configuration line are superseded as universal requirements. They remain valid only as optional deployment choices after the same capability, identity, policy, and evaluation checks as any other adapter. This agrees with ADR-004 and ADR-016.

**Migration and contract impact.** The `InstructionGraph` schema stays at `ai.ecosystem/v1alpha1`; this decision strengthens canonical content without changing its wire shape or runtime authorization semantics. All managed client projections are regenerated from `.ai/instructions.yaml`, yielding a new source digest. Existing runtime journals, M2/M3 contracts, and signed evidence are unaffected. Future documents must qualify ecosystem stack levels as `E*` and loop maturity levels as `L*`; ambiguous bare `L0–L4` architecture references should be migrated when their owning documents are next revised.

**Evidence.** `eco validate`, deterministic projection rendering, `eco render --check`, and projection-focused regression tests verify that the canonical graph and all managed surfaces agree. These checks establish governance consistency; they do not by themselves prove runtime enforcement, which remains covered by the broker, policy, store, and isolation tests.

## ADR-019 — Verification-only external trust bootstrap

**Date:** 2026-07-16

**Context.** M3.5 made the complete embedded runtime composition reachable, but intentionally stopped before a live repository read. That gate requires a repository snapshot and deployment-conformance observations which are both authentic, fresh, bound to the exact project/deployment/suite, and provisioned without committing credentials. Letting the executable workflow generate and sign its own snapshot or a passing conformance record would make the claimed trust boundary circular: a compromised runtime could manufacture the evidence it needs to authorize itself.

**Decision.** `.ai/trust.yaml` is the canonical, declarative bootstrap policy for a future deterministic read-only workflow. It contains no private key, signed envelope, provider credential, endpoint, prompt, response, or evidence body. It declares only:

- strict external environment references for verification keys and envelope files;
- bounded issuer/key allowlists for `RepositorySnapshot` and `AdapterConformanceProfile` records;
- the one external operator identity expected to issue a repository snapshot, its maximum file size, and explicitly classified repository entries;
- immutable trusted evaluation-suite digests and the exact deployment/suite/envelope inputs a workflow must verify.

The executable runtime is verification-only. It must resolve only the exact `env:ECO_*_EVIDENCE_KEY` and `env:ECO_*_ENVELOPE_FILE` references declared by this policy; it must not enumerate environment variables, echo their names or values in diagnostics, or accept an arbitrary path/issuer/key selected by a model or task. An envelope-file resolver is a trusted adapter: it must apply its own ownership, permission, size, canonical-byte, and symlink/reparse safety checks before supplying bytes to `EvidenceTrustStore` and `TrustedEvidenceIngestor`. The existing policy engine then re-verifies canonical signed bytes and their project/root/deployment/suite/identity/time bindings at authorization boundaries.

The current executable compatibility profile is explicitly `HMAC-SHA256` / `local-shared-key`. Its signing ceremony is external to the workflow and belongs to the operator-controlled evidence authority. The runtime receives the verification material only through the configured external resolver and may never invoke `HmacEvidenceSigner` as part of trust bootstrap, runtime doctor, `wiki-health-check`, or policy execution. HMAC can authenticate an embedded shared boundary but does not provide third-party non-repudiation, compromise separation between a signer and verifier that possess the same key, or provider-model provenance. A signed `AdapterConformanceProfile` means only that the configured authority observed the bounded suite against the declared deployment identity; it must not be described as an attestation of immutable provider weights, general model quality, or provider-origin evidence.

**Consequences.** A missing envelope, missing externally provisioned key, malformed/noncanonical evidence, unlisted issuer, unbound project/deployment/suite, expired observation, mismatched root identity, or insecure evidence-file resolution must leave execution blocked. A valid canonical trust manifest alone grants no model access, repository read, write authority, egress, or provider claim. The next integration slice may add a verification-only `eco runtime trust doctor` and then an actual read-only workflow only after it consumes real externally signed evidence. Asymmetric verification keys, hardware-backed/operator identity, rotation/revocation, and Windows/macOS evidence-file safety require separately versioned contracts and conformance evidence.

## ADR-020 — Separate no-model A1 lifecycle and fixed L0–L2 promotion gate

**Date:** 2026-07-16

**Context.** M3.6 could verify a fresh externally signed repository snapshot but intentionally could not execute `wiki-health-check`. The existing `RunPlan` is model-routed: it selects a deployment, owns model/tool budgets, and enters an adapter lifecycle. Reusing that record for deterministic file inspection would create a false audit claim that a model route existed. A generic workflow language, caller-selected path list, or prompt-defined policy would also let a low-risk first loop silently expand its own authority. Finally, a successful one-shot read is not enough evidence for repeatability, recovery, or promotion.

**Decision.** The first M4 profile uses separate `NoModelRunRequest`, `NoModelRunPlan`, and `NoModelReadRequest` contracts plus explicit no-model lifecycle events. The only workflow id is `wiki-health-check`. Code owns the exact three-path scope; durable plans expose only three opaque slot/entry digests, not raw paths. Policy rebinds every plan to the current canonical config, signed snapshot digest/root/provenance, D0/P1 classifications, exact slot mapping, and frozen budget. The plan has no route and fixes three reads, a 30-second wall-clock bound, the exact signed input-byte sum, and zero model, network, or workspace-write requests.

The runtime verifies external trust before opening state, consumes one plan allow, then issues and consumes one expiring single-use decision per read. Repository bytes cross only `RepositoryReadBroker`; no adapter, endpoint, provider credential, network transport, artifact/write store, approval service, or write broker is constructed. In-memory checks establish signed byte integrity, one primary heading outside fenced code per document, and three distinct document digests. Reports and events contain only fixed status values, ids, counts, and digests.

M4 uses a dedicated SQLite profile rather than pretending that the model-budget schema-v3 store already supports no-model semantics. Its database must live in a pre-existing private external state directory and has a fixed application/schema id. Unexpected objects, insecure permissions/ownership, repository placement, symlinks, hardlinks, malformed state, wrong keys, or HMAC/head/event mismatch fail closed. A separate environment-provisioned HMAC key authenticates plan/event/head state. HMAC does not provide external rollback detection, third-party identity, or non-repudiation; those require an independent anchor or signed service boundary.

Recovery always reconstructs policy from current external signed evidence. Each attempt persists `requested → allowed → started` before broker I/O. Only a pre-start `allowed` read may receive a fresh decision and retry; a recovered `started` state is an ambiguous outcome and becomes a terminal typed failure without another broker call. Completed reads restore sanitized digest/heading evidence and are not repeated, and a terminal run replays with zero broker reads. The first durable event anchors the 30-second deadline across recovery, while monotonic elapsed time advances policy freshness checks before reads, after parsing, and before success.

Promotion is a second versioned contract. Exactly five independent fixed journals plus one zero-read replay must agree on snapshot/report/count/bytes and show zero unauthorized actions, repository mutations, model/network requests, writes, adapters, and content emissions. Passing grants eligibility only for L0 manual, L1 repeatable, and L2 observe/report-only behavior. L3 proposal, L4 controlled apply, and L5 evidence-compounding are structurally ineligible for this profile. Thresholds are schema constants; CLI callers cannot lower them.

**Consequences.** `eco run wiki-health-check` and `eco eval wiki-health-check` are executable only with externally provisioned signed evidence, verification material, a private external state directory, and a distinct journal key. They expose no caller-controlled path, model, deployment, endpoint, workflow file, retry count, or threshold. The completed profile is Linux/WSL-specific because it relies on the existing `openat2` broker. It does not implement full-wiki link crawling, semantic staleness detection, edits, scheduling, autonomous retries, or production/team evidence identity. Any wider scope or L3–L5 behavior requires a new contract and evaluation corpus rather than modification through prompt data.

**Evidence.** Contract, policy, state, journal, execution, recovery, mutation-resistance, repository-nonmutation, deadline, structural-health, five-attempt stability, recovery, threshold-tampering, and explicit L3–L5 denial tests pass with the complete project suite. See [M4 no-model wiki health](../architecture/no-model-wiki-health.md) and the [M4 completion report](../research/2026-07-16-m4-no-model-wiki-health-completion-report.md).

## ADR-021 — Preview-bound, receipt-owned project adoption

**Date:** 2026-07-16

**Context.** The ecosystem must be usable in arbitrary projects and by different AI clients, but the original `eco init/render/uninstall` workflow was an expert-oriented compiler interface rather than a safe installer contract. A generic recursive copy or deletion would silently claim existing `.ai` files, overwrite instruction surfaces, normalize their bytes, leak discovery data, or make uninstall unable to distinguish user-owned and ecosystem-owned state. Platform portability also cannot be inferred from the fact that Python can write files: the Linux/WSL broker, isolation, and controlled-write backends have independent security proofs.

**Decision.** M4.5.1 introduces a separate `adoption.ai.ecosystem/v1alpha1` lifecycle. `eco adopt --dry-run` emits a deterministic content-minimized `ProjectAdoptionPlan`; `eco adopt --apply PLAN_SHA256` acquires a per-repository lock, recomputes the plan, and applies only an exact digest match. The digest is a stale-preview guard, not authentication or runtime approval.

Fresh, existing-config, and reinstall modes are distinct. Existing canonical config requires explicit `--adopt-existing-config` and remains `preexisting`. Existing client surfaces are preserved as byte-exact before-images. A schema- and semantics-validated `.ai/adoption.json` records canonical, projection, and generated-file ownership. Render state binds every installed projection digest and every backup path, full digest, and size; backup paths are restricted below `.ai/.state/backups` and must be singly linked regular files. Marker text without valid ownership state never authorizes uninstall.

Full removal first validates the complete receipt/config/projection/state/backup/unknown-entry set without writing. It then uses the projection uninstaller and removes only an enumerated exact-digest owned set plus empty parents. Recursive deletion of an unverified `.ai` tree is prohibited. Apply uses bounded best-effort rollback; every rollback write is conditional on the live file still matching the exact ecosystem-written after-image. A concurrent user edit is preserved and produces `ECO_ADOPTION_ROLLBACK_CONFLICT` rather than being overwritten.

Discovery may initialize descriptive language/build metadata but cannot infer or execute repository commands. Plans and JSON failures contain relative paths, counts, digests, and stable codes only; they exclude source text, secret values, and absolute repository paths. Custom config roots remain unsupported in this contract version.

**Consequences.** Adoption behavior can be tested on Linux, macOS, and Windows without claiming that runtime enforcement is portable. The receipt and render state are strict local ownership metadata, not cryptographically authenticated team identity. M4.5.1 does not provide a durable crash journal: an uncatchable process/host failure may leave a partial install requiring a new preview or manual recovery. It also does not prove hostile parent-directory swaps, complete Windows reparse/case-fold safety, packaging, or any non-Linux runtime broker. M4.5.2 must define platform/adapter capability profiles and conformance evidence; unsupported controls remain unavailable rather than using a weaker fallback.

**Evidence.** Byte-exact Python and TypeScript-monorepo fixtures cover fresh/existing/reinstall, CRLF/no-final-newline restoration, stale plans, secret minimization, path escape, symlink/hardlink/non-UTF-8 rejection, schema validity, no-op mtimes, backup/state tampering, ownership forgery, concurrent-edit rollback conflict, full-removal preflight, and lock contention. See [M4.5.1 project adoption](../architecture/project-adoption.md) and the [completion report](../research/2026-07-16-m4.5.1-adoption-bootstrap-report.md).

## ADR-022 — Passive platform and adapter description cannot mint runtime proof

**Date:** 2026-07-16

**Context.** M4.5.1 can install the canonical contracts and projections on Linux, macOS, and Windows, but portable file installation does not make the Linux/WSL read broker, process isolation, controlled-write backend, credentials, routing, or loops portable. A conventional platform doctor often runs installed tools, reads environment state, contacts endpoints, or treats a discovered binary/container/GPU as proof of a capability. It could then become both the producer and consumer of the evidence that authorizes it.

**Decision.** M4.5.2 introduces the separate `platform.ai.ecosystem/v1alpha1` `PlatformProfile` and `AdapterCapabilityProfile` contracts. Both are content-minimized description records. Operator declaration, passive detection, authenticated proof, and effective policy capability remain distinct states. In this passive contract version, profile proof is null, adapter/runtime proven state is forbidden, every effective flag is false, and aggregate effective-capability lists are empty.

`eco platform doctor --json` performs bounded categorical inventory only. It derives a coarse OS/context, resolves ten allowlisted executable names without invoking or opening them, and checks five fixed client projection locations using regular-file metadata without reading content. Search-path resolution may consult the process `PATH`/platform equivalent, but those values and resolved locations are never emitted or digested. It emits no command output, host identity, endpoint, model, credential, package list, device details, or raw exception. It creates no broker, adapter, model, loop, process, network access, write, or runtime authority. Mutable context hints without corroboration and overlapping strong contexts fail closed.

The new `AdapterCapabilityProfile` does not replace or weaken runtime `AdapterConformanceProfile`. The former is fixed to declaration/inventory authority and cannot contain proven/effective capabilities. The latter remains externally produced, authenticated, freshness-bounded, deployment/suite/identity-bound evidence which the runtime must re-verify at its authorization boundary. A doctor report or semantic digest is not a signature, attestation, or capability token.

**Consequences.** The same profile classification and schema behavior can run in hosted Linux/macOS/Windows tests without claiming that native security controls exist on those hosts. Executable presence does not prove version, provenance, safety, or usability; client-surface presence does not prove client loading or compliance. Hosted-CI classification in the current matrix is a normalized fixture rule rather than trusted public-runner attestation. Environment-reference resolution, shell/process behavior, filesystem race semantics, model/CUDA/NIM functionality, and native broker/isolation/write safety remain `not-tested` until separate controlled runners produce exact-bound authenticated evidence.

M4.5.3 packaging may consume these descriptors but cannot turn detection into installation authority or runtime proof. It must preserve the M4.5.1 preview/ownership/uninstall boundary and leave unsupported controls unavailable without fallback.

**Evidence.** Six deterministic fixtures cover Linux native, WSL, macOS, Windows native, container, and hosted CI. Adversarial tests reject unknown/duplicate/spoofed/nested inputs and unsigned evidence, verify schema/digest/identity closure, trap process/network/write/secret access, and compare repository bytes and mtimes before/after the CLI call. See [M4.5.2 architecture](../architecture/platform-adapter-conformance.md) and the [completion report](../research/2026-07-16-m4.5.2-platform-adapter-conformance-report.md).

## ADR-023 — Distribution integrity, package installation and project adoption are separate boundaries

**Date:** 2026-07-16

**Context.** A convenient installer can blur download provenance, package-manager effects, project bootstrap and runtime capability. Passive platform detection must not select an installer or turn a successful Python install into native security proof.

**Decision.** M4.5.3 defines a closed wheel-only `DistributionManifest` and verifies an exact local wheelhouse, lock digest, package/schema inventory and wheel internals before any package-manager execution. `eco distribution verify` and the standard-library verifier perform no install, network, process, project mutation or authority creation. `eco distribution plan` emits argv previews with `executionReady: false`; only the Linux private-venv `pip --no-index --find-links` path is exercised as a real reference smoke. Installing/upgrading/removing the Python package and preview/apply/removing a repository adoption remain independent lifecycles.

Manifest SHA-256 proves integrity, not publisher identity. `originAuthentication: not-attested` is mandatory in this profile. Public provenance, revocation, SBOM and immutable verified-byte staging require later authenticated release infrastructure and cannot be inferred from the package verifying itself.

**Consequences.** A portable CLI install does not create broker, adapter, model, write, loop or native-backend authority. `pipx` and `uv tool` are non-executable plan adapters until separate manager/platform gates exist. See [portable distribution](../architecture/portable-distribution.md) and the [M4 portability report](../research/2026-07-16-m4-portability-completion-report.md).

## ADR-024 — Active backend conformance produces observation, never effective authority

**Date:** 2026-07-16

**Context.** M4.5.2 intentionally cannot prove a platform, while native security controls need controlled live tests. Allowing a runtime to choose, run, sign and consume its own suite would create circular authority.

**Decision.** M4.6 adds the separate explicit `eco conformance run` surface. It accepts only the fixed `linux-namespace-boundary` suite, an exact suite digest, a private empty external test root and exact platform/distribution/backend-instance bindings. Synthetic probes test only the existing namespace/Landlock launcher's exact seeded clean environment, work-directory boundary, network denial, output/deadline bound, read-only mode and closed stdin. Live context detection is independent of the supplied profile. The runner emits an unsigned `PlatformBackendConformanceProfile` with `observedCapabilities`; failure/unsupported results have none. External evidence ingestion additionally pins the runner and backend-implementation digests and remains non-authorizing.

An external controller may sign the exact record. Dedicated ingestion re-verifies issuer, freshness, suite, platform, distribution and backend-instance binding but has no runtime-policy consumer in M4.6. HMAC means local shared-key authentication, not third-party identity. Windows, macOS, containers and hosted CI remain negative fixture profiles.

**Consequences.** Passive doctor remains process/network/write-free. Conformance cannot create effective capability, route, broker, adapter, model, store, approval, write or loop authority. See [platform backend conformance](../architecture/platform-backend-conformance.md) and the [M4 portability report](../research/2026-07-16-m4-portability-completion-report.md).

## ADR-025 — Signed team declarations authenticate bytes but do not create authority

**Date:** 2026-07-16

**Context.** M1–M4 use local labels and embedded HMAC boundaries. They can enforce the bounded single-operator runtime profile, but they cannot represent portable team principals, independently verifiable policy provenance, shared revocation or distinct-person approval. Simply adding public keys to an unsigned policy would be circular, and accepting a valid signed document as current runtime policy would make replayed or project-controlled bytes an authorization token.

**Decision.** M5 begins with a separate `authority.ai.ecosystem/v1alpha1` namespace for closed team, principal, membership, identity-key and policy-bundle declarations. The initial bundle is fixed to `identity-catalog-only` and `deny-all`; all records structurally deny permission, activation, private-key presence and runtime-authority creation.

Policy envelopes use exact Ed25519 signatures over domain-separated canonical JSON. M5.2 verification uses an immutable caller-supplied `PolicyTrustAnchor` outside the project and reports verification only relative to that anchor; it does not establish anchor provenance. A matching key inside the signed catalog binds the envelope but cannot bootstrap trust. Production signing and private-key input remain absent from the runtime and CLI. An independently provisioned resolver or OS trust-store adapter is required before activation.

Runtime and authority schema registries/digests are separate. Existing M4 schema snapshots, `.ai/trust.yaml`, HMAC evidence, policy decisions and stores are unchanged. `eco policy verify`, `policy inspect` and `identity inspect` are diagnostic-only: authenticity or structural validity does not establish latest revision, effective status, revocation freshness, permission, activation or runtime authority.

**Consequences.** M5.3 may add RBAC/ABAC only as a narrowing gate intersected with the existing `PolicyEngine`, never as a second allow oracle. M5.4 must add a durable monotonic activation head before a signed revision can be called current. Revocation/rotation/emergency state and quorum permits require later explicit contracts and effect-boundary rechecks. PostgreSQL/network services, SSO, hardware-backed signers, HA and enterprise topology remain M6.

**Evidence.** Five packaged schemas, semantic/cross-record validators, Ed25519 verification, descriptor-safe CLI reads, dependency lock and 405-test regression pass. Adversarial tests cover digest/field/signature tamper, algorithm confusion, self-bootstrap, wrong team/project/key, duplicate/noncanonical JSON, time windows, unsafe file aliases, output sanitization and zero mutation. See [M5 team authority](../architecture/team-authority.md) and the [M5.0–M5.2 report](../research/2026-07-16-m5-team-authority-foundation-report.md).

## Supersession

Decisions are not silently edited after implementation evidence contradicts them. Add a dated superseding decision with evidence, migration impact, and affected contract versions.
