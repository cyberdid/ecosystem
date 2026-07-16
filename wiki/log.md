# Wiki Log

Append-only хронологічний лог операцій. Формат: `## [YYYY-MM-DD] тип | назва`

---

## [2026-07-16] implementation | Remaining bounded M4 portability completed

- Added M4.5.3 closed distribution integrity metadata, installed + standard-library offline verifiers, exact main/dependency/lock/schema binding, wheel-internal validation and non-executable package-manager previews.
- Added a real `0.6.0` build/verify/private-venv `--no-index` install smoke and focused Linux/macOS/Windows contract gates. Package installation remains separate from project adoption; checksum integrity remains separate from publisher provenance.
- Added M4.6 `eco conformance run`, separate from passive doctor, with one fixed synthetic Linux/WSL namespace + Landlock suite and a private external test-root boundary.
- Added `PlatformBackendConformanceProfile`, exact external HMAC envelope ingestion and narrow observed capabilities. No policy/store/broker/model/adapter/loop consumes the record; unsupported/failure profiles expose no capabilities.
- Multi-agent review found and closed an ignored `uv.lock` tamper path, fake/non-PEP-427 wheel acceptance, missing main metadata/entry-point checks, dependency-wheel non-validation, verifier reopen races, archive-budget/file-type gaps, numeric JSON aliases, active-context relabeling, unpinned runner/implementation evidence, an unseeded environment canary, non-object CLI input, and standalone contract divergence.
- Local evidence: 381 complete tests, 17 distribution tests, 7 backend-conformance tests, 7 live isolation tests, one real WSL conformance pass, compile/schema/diff gates, and real eight-artifact offline installation pass.
- Hosted GitHub Actions run `29498793136` passed at commit `9dc77bee4772294f010c1ff0d5d2c86b7fb1b29a`: full Linux plus focused macOS/Windows portability gates are green. The initial run exposed and drove correction of non-canonical temporary fixture paths on both hosted operating systems.
- Added ADR-023/024, architecture pages, combined completion report and wiki handoff to M5 team identity/signed policy/RBAC.

## [2026-07-16] implementation | M4.5.2 passive platform and adapter conformance completed

- Added closed `platform.ai.ecosystem/v1alpha1` `PlatformProfile` and `AdapterCapabilityProfile` contracts with semantic digests, exact inventory/identity checks, and structurally empty effective-capability state.
- Added deterministic `eco platform doctor --json` with optional operator-declared profile comparison, coarse OS/context classification, allowlisted executable-name resolution, fixed client-surface metadata, and fixed safety flags.
- The doctor cannot accept unsigned evidence, invoke an executable, contact a network or adapter, read secret/projection content, write files, or create runtime authority. Existing externally signed runtime `AdapterConformanceProfile` remains the separate proof boundary.
- Six fixtures cover Linux native, WSL, macOS, Windows native, container, and hosted CI. Spoofed hints, unsupported/inconsistent OS, duplicates, unknown fields, declaration mismatch, and nested WSL/container/CI contexts fail closed.
- Multi-agent review found and closed unsigned effective-capability schema elevation, incomplete exact-inventory reconciliation, and a Python 3.12 test nesting limit. Canary traps cover process, shell, network, HTTP, secret reads, and filesystem mutation.
- Local verification: 8 focused platform tests, 357 complete `unittest` tests, 357 pytest tests plus 205 subtests, compile, lock, validation, drift, both doctors, deterministic diff, wheel contents, and whitespace checks pass.
- Hosted GitHub Actions run `29493436362` passed at implementation commit `34411106fb3b02aca1422f485b93dd9069cfe029`: full Linux plus focused macOS and Windows portability jobs are green.
- Added ADR-022, architecture documentation, completion research, and the M4.5.3 portable-packaging handoff. Active native security conformance remains a separate non-claim.

## [2026-07-16] implementation | M4.5.1 safe project-adoption bootstrap completed

- Added schema-valid `ProjectAdoptionPlan` and `ProjectAdoptionReceipt` contracts plus mandatory `eco adopt --dry-run` / exact-digest `--apply` lifecycle for fresh, explicit existing-config, and reinstall modes.
- Added content-minimized discovery, in-memory starter validation, byte-exact projection before-images, deterministic no-op reinstall, an external per-repository apply lock, owned `.ai/adoption.json`, and ignored private render state.
- Replaced recursive config deletion with complete receipt/state/backup/config/unknown-entry preflight and enumerated removal; marker text without strict ownership state never authorizes a mutation.
- Multi-agent adversarial review reproduced and closed text-normalized restoration, stale partial apply, symlink/hardlink/path escape, non-UTF-8, unauthenticated backup restore, marker-only ownership forgery, and rollback overwriting a concurrent user edit.
- Rollback is deliberately bounded and compare-and-swap aware: it restores only exact ecosystem-written after-images and preserves conflicting user bytes. Durable `SIGKILL` recovery, hostile parent swaps, complete reparse/case-fold safety, packaging adapters, and non-Linux runtime backends remain non-claims.
- Added byte-exact Python and TypeScript-monorepo fixtures, 29 focused adoption tests, Linux/macOS/Windows hosted adoption jobs, ADR-021, architecture documentation, completion research, and wiki handoff to M4.5.2.
- Final local gate: 349 `unittest`; 349 pytest tests plus 188 subtests; compile, wheel/schema packaging, `uv lock --check`, validation, projection drift, doctor, diff, and whitespace checks all pass.
- Hosted GitHub Actions run `29491034403` passed at commit `93122d0ab290de5e95f19a8e95551e9c6626868a`: full Linux gate plus focused macOS and Windows adoption/validation/projection/doctor jobs. The Windows run first exposed CRLF-sensitive canonical instruction digests; `.gitattributes` now fixes canonical YAML and generated projection surfaces to LF.

## [2026-07-16] implementation | M4 fixed no-model wiki-health L0–L2 profile completed

- Added distinct route-free `NoModelRunRequest`, `NoModelRunPlan`, and `NoModelReadRequest` contracts plus an exact no-model lifecycle; the plan fixes three D0/P1 slots, three reads, 30 seconds, exact input bytes, and zero model/network/write budgets.
- Added `eco run wiki-health-check`: external signed-snapshot verification, single-use plan/read decisions, Linux/WSL broker-only reads, in-memory integrity/H1/distinctness checks, and path/content-free output.
- Added a private external SQLite application with separate HMAC plan/event/head authentication, strict ownership/permissions/schema/link checks, exclusive process ownership, fresh pre-start recovery authorization, a durable `started` ambiguity fence, and terminal zero-read replay.
- Added `eco eval wiki-health-check`: five fixed independent journals plus a zero-read recovery proof, frozen thresholds, deterministic promotion report, maximum L2 eligibility, and structural L3–L5 denial.
- Multi-agent adversarial review reproduced and closed forged recovery authority, adapter/lifecycle entry, duplicate-scope success, unauthenticated journal rewrite, symlink repository mutation, timestamp replay conflict, concurrent journal ownership, recovery-without-reauthorization, partial-recovery evidence loss, ambiguous post-read reread, parser-deadline, and frozen policy-time gaps.
- Full local acceptance gate: 320 `unittest` tests plus pytest, compile, canonical validation, render drift, doctor, and diff checks. Exact proof limits are in the M4 completion report and ADR-020.
- Hosted Linux GitHub Actions run `29486870506` passed all declared gates for implementation commit `3092f1f4e62622ced8e7047ad39243ed5a11a5be`.

## [2026-07-15] implementation | M3 bounded controlled-write profile completed

- Added exact A2 `repository.write` contracts for one Linux/WSL UTF-8 regular-file create/replace operation, with active-plan, snapshot, root, before-state, candidate, preview, limit and rollback bindings.
- Added a separate authenticated write authority that atomically consumes human approval and policy decision, binds idempotency, locks the target, fences leases and detects SQLite/audit tampering without storing raw paths or content.
- Added descriptor-anchored atomic apply and compare-and-swap rollback with protected-path, traversal, symlink, hardlink, race, content, mode and fault-injection defenses.
- Added private-CAS recovery bundles and full process-loss recovery: exact before becomes failed, exact after is rolled back, and unrelated state remains `recovery_required`.
- Closed adversarial review findings for proposal substitution, root mismatch, inactive plans, policy reuse, expired terminal replay, detect-only recovery and stale lease timestamps.
- Final deterministic regression gate: 258/258 `unittest`; full pytest, compile, validation, render, doctor, lock and diff gates are required by the completion report.

## [2026-07-15] security | M2 adversarial closure passed

- Removed the last production-callable unsigned fixture path and arbitrary verifier injection: `PolicyEngine` now owns a verifier built from exact immutable issuer policies.
- Bound allow-decision expiry to envelope/observation/snapshot validity and added evidence re-verification at plan activation, closing the plan-before-expiry/activate-after-expiry gap for both in-memory and durable paths.
- Added OS-level atomic no-replace publication plus a domain-separated signed manifest over all evidence files, including full sanitized RunRequest, RunPlan, PolicyDecision, and receipts.
- Disabled Claude user/project/local setting sources, forced a strict empty MCP configuration, and rechecked executable/model identity after invocation.
- Authoritative closure: `.ai/evals/live/2026-07-15-m2-closure-pass/`; suite `08d7ee84...26dd6`, aggregate evidence `1c7e8d1a...e46927`, publication manifest `fabdb4d7...d624`.
- Final automated gate: 187/187 `unittest`, full `pytest`, compile/package checks, canonical validation, render drift check, doctor, and diff check.

## [2026-07-15] hardening | Final M2 trust and live-policy gate

- Removed the production `TrustedRuntimeRecord`/unsigned-evidence bypass surface. `PolicyEngine` now accepts signed envelope bytes with explicit trust context, re-verifies them at construction/planning/tool authorization, and binds issuer/key/envelope provenance into `RunPlan`.
- Restricted the Linux/WSL launcher to untrusted-agent execution: credential bindings are rejected before resolution; stdin is closed; stdout/stderr are bounded; resolver failures are sanitized.
- Re-ran the `text-basic` live suite against manifest-verified Ollama/Qwen and executable-verified Claude CLI. Final suite digest is `08d7ee84...26dd6`; aggregate evidence digest is `9397ad2f...3dd17`.
- Published both observations as independently ingestible HMAC envelopes. Both passed trust-policy ingestion, and the local D0 envelope passed a real production `PolicyEngine` allow-plan gate.
- Final automated gate is 181/181 tests; retained final evidence is under `.ai/evals/live/2026-07-15-m2-final/` and is no-overwrite/atomically published.

## [2026-07-15] decision | Hardware-neutral M2 identity and evidence boundary

- Accepted ADR-016: DGX is an optional local compute profile, not an M2 dependency; the active gate is one governed local deployment plus one governed cloud deployment.
- Recorded that a cloud model alias is an observable routing identity, not attestation of immutable provider weights or serving internals.
- Clarified that the live observations have a 24-hour validity window: expiry preserves historical evidence but removes current routing/promotion authority until renewal.
- Replaced the broad “content-free” wording for evaluation artifacts with “raw-content-free D0 evidence”; deterministic low-entropy digests may still be guessable.
- Updated architecture and roadmap handoffs from “Next M2/DGX” to the M2 regression baseline and M3 controlled-write gate. Evidence files and their digests were not changed.

## [2026-07-15] implementation | M2 embedded read-only reference profile completed

- Added pinned local-loopback and direct-cloud adapter contracts, credential-free invocation objects, exact endpoint/model identity, strict bounds, sanitized failures, and no automatic fallback.
- Added signed trusted-evidence ingestion for repository snapshots and adapter observations. `PolicyEngine` now rejects unsigned runtime evidence by default; raw records require an explicit test-only flag.
- Added descriptor-anchored Linux snapshot generation and a Linux/WSL launcher using user/net/pid namespaces, Landlock filesystem/TCP denial, clean environment, exact credential references, executable allowlist, timeout, and fail-closed preflight.
- Added deterministic cross-deployment evaluation with signed sanitized evidence and live reference adapters for loopback Ollama and broker-owned Claude CLI.
- Captured a passing live suite across Ollama 0.32.0 / Qwen3 0.6B and Claude Code 2.1.202 / Claude Sonnet 5. Raw prompt, output, endpoint, credential, path, provider body, session, and UUID values are absent from retained evidence.
- Removed the DGX dependency from canonical deployment templates and marked the old DGX inventory as historical/unavailable.
- Final gate: 172/172 `unittest`, full `pytest`, compileall, canonical validation, projection drift check, doctor, and diff check pass. Exact limits remain documented in the M2 completion report.

## [2026-07-15] implementation | M2 deterministic cross-deployment evaluation runner

- Added one vendor-neutral runner protocol for the same immutable suite across pinned local and cloud adapters; deterministic mocks exercise the protocol without network access or provider credentials.
- Normalized only Unicode/newline transport variance, retained output and usage differences, and required explicit per-case usage tolerances.
- Emitted schema-valid `AdapterConformanceProfile` observations plus canonical HMAC-signed evidence binding suite, exact identities, safe probe results, pairwise comparison, and observation digests.
- Kept prompts, outputs, endpoints, provider bodies, exception text, credentials, and paths out of evidence. Timeout is fail-closed for evidence; physical request cancellation remains a real-adapter obligation.
- Focused parity, output/usage divergence, timeout, identity mismatch, deterministic reproduction, and tamper tests pass 5/5.
- M2 remains open: mocks are implementation evidence, not live DGX/cloud evidence. Pinned deployments, trusted ingestion, OS credential/egress isolation, and one passing real suite digest are still required.

## [2026-07-15] implementation | M2.5 embedded durability completed

- Upgraded the authority schema to v3 with full immutable event baselines, store-generated native run events, deterministic replay, exact lifecycle/producer/issuer/subject/result reconciliation, and terminal full-projection checkpoints.
- Removed the broker's policy/budget authority. The typed embedded orchestrator now re-evaluates through its configured policy engine and executes atomic PREPARE, filesystem-only read, artifact fsync/proof, and SUCCESS/FAILURE.
- Adopted explicit `no_retry` recovery: an expired PREPARE cannot repeat I/O, exact fencing epoch is required, byte reservations are released, and spent tool attempts remain spent. Added real process-exit and concurrent writer/verifier tests.
- Added a private content-addressed artifact store with streamed digest/length, private temporaries, fsync, atomic no-clobber install, HMAC availability proofs, reopen byte verification, and safe crash-temp cleanup.
- Added authenticated v2→v3 migration without synthetic history, immutable read-only backup verification, authenticated online backup/no-overwrite restore, historical HMAC keyring, atomic dual-auth rotation with stable path-HMAC, external anchor chains, and optional startup anchor enforcement.
- Multi-agent P0 reviews covered event/reducer semantics, orchestrator authority, crash/recovery, artifact durability, migration, backup/rotation/anchor, and negative-test gaps. The completed boundary and its remaining limitations are recorded in `docs/research/2026-07-15-m2.5-completion-report.md`.
- Full suite contains 146 tests. M2 remains open only for pinned DGX/cloud adapters, identical cross-deployment evaluation, trusted snapshot/observation ingestion, and OS network/credential isolation.

## [2026-07-15] implementation | M2.5 pure run-event reducer checkpoint

- Extracted all run and tool lifecycle transitions into immutable `RunProjection` plus the side-effect-free `reduce_run_event` function; `RunEventChain` now delegates to this shared reducer instead of owning a second transition implementation.
- Kept producer capability, issuer, sequence, timestamp, and digest-chain checks at the event-ingress boundary while making the transition core reusable for durable SQLite replay and verification.
- Closed the `tool.failed` semantic gap: both completed and failed terminal tool events now require a `resultDigest`, preventing a failed event from being detached from its exact `ToolExecutionOutcome`.
- Added direct reducer tests for deterministic output, canonical tool projection ordering, caller-input immutability, and failure without partial state mutation.
- Full suite passes 116 tests; `compileall` and `git diff --check` are green.
- Next: define explicit event-history bootstrap mode, durable producer identity, atomic append/replay, and event integration into plan activation plus repository PREPARE/COMMIT without synthesizing missing historical events.

## [2026-07-15] implementation | M2.5 authoritative plan, budget, and repository-operation store

- Upgraded the fresh-store schema to v2 with authoritative `runs`, `plans`, `budgets`, `operations`, `budget_reservations`, `run_events`, and authenticated `authority_revisions`; legacy schema migration remains an explicit future ceremony rather than an implicit rewrite.
- Implemented exact plan issuance/activation, one active plan, initial-input accounting, and a deadline derived from immutable plan creation time that survives reopen and never extends on reclaim.
- Implemented atomic repository-read PREPARE: exact plan/snapshot/request/decision/intent binding, single-use allow consumption, conditional tool/input budget spend, content-free intent, reservation, and bounded lease in one `BEGIN IMMEDIATE` transaction.
- Implemented success/failure COMMIT, exact receipt/artifact/error/outcome reconciliation, exactly-once logical outcome/accounting, byte commit/release, tool-attempt preservation, lease reclaim with fencing epochs, recovery scan, and deterministic fail-closed abort after deadline.
- Replaced guessable plain path hashes with store-scoped domain-separated HMAC references; raw path/content remain absent from records, audit, DB, WAL, and SHM tests. Failure records are code-owned and reject arbitrary `causeRef`/details.
- Added distinct opaque policy/broker composition capabilities, exact policy/profile provenance checks, bounded owner IDs, authority-managed record APIs, and coherent single-snapshot verification across concurrent connections.
- Multi-agent adversarial review found and drove fixes for orphan nonces, mutable decision projection tampering, deadline-bypassing leases, policy provenance bypass, failure-metadata leakage, unauthenticated lease claiming, managed-record self-corruption, mixed-snapshot verification, and post-deadline stuck reservations.
- Full suite passes 112 tests; `compileall` and `git diff --check` are green. Canonical CLI validation/projection/doctor checks are rerun after this documentation update.
- Remaining M2.5 work: durable event/checkpoint reducer integration, typed store→broker orchestrator, opaque/encrypted retry payload handle or explicit no-retry profile, process-kill crash matrix, v1 migration, artifact availability proof, external audit anchor, and durable multiprocess issuer identity.

## [2026-07-15] implementation | M2.5 durable journal foundation

- Added content-free `ToolExecutionIntent`, `RepositoryReadReceipt`, `ToolExecutionOutcome`, and `RunCheckpoint` contracts for a crash-consistent PREPARE/read/COMMIT protocol.
- Implemented `SQLiteRuntimeStore` for allowlisted safe records and durable single-use decisions with WAL, `synchronous=FULL`, `BEGIN IMMEDIATE`, private POSIX permissions, immutable IDs, canonical bytes, exact idempotency, and UTC expiry.
- Added a global SHA-256/HMAC audit chain plus reconciliation back to records, decisions, and nonces; wrong keys, row/audit tampering, record+digest rewrites, and reopening a consumed decision fail closed.
- Raw `ToolRequest`, `RepositorySnapshot`, prompts, tool content, and credentials are rejected from the journal; privacy tests scan database/WAL/SHM files for a sentinel path.
- Independent agent design defined the next authoritative SQLite schema, two-transaction repository-read orchestration, recovery rules, and model adapter/endpoint/egress boundary.
- Full suite now passes 96 tests; compile, canonical validation, projection drift, doctor, and diff checks remain green.
- Remaining: migrate active run/event/budget authority into SQLite, crash-injection recovery, external audit anchor, authenticated snapshot/observation ingestion, and model adapter/isolation work.

## [2026-07-15] implementation | M2 embedded enforcement and read-only broker slice

- Implemented the embedded default-deny `PolicyEngine`: exact route/observation/tool intersection, immutable plans, single-use expiring decisions, no fallback, typed denials, full canonical schema defense, and future-time rejection.
- Implemented a capability-scoped `RunEventChain` with digest linkage, strict producer/outcome semantics, correlated tool lifecycles, explicit cancellation, success/exhaustion preconditions, and terminal-state enforcement.
- Implemented one runtime-owned atomic `BudgetLedger` per active plan, including initial-input accounting, concurrent request limits, monotonic duration, model-usage accounting, and input-byte reservations.
- Added the `RepositorySnapshot` contract and bound it into `RunPlan`; unknown, protected, D4, higher-class, or changed entries fail closed.
- Implemented the Linux/WSL `repository.read` broker with `openat2`, root-descriptor anchoring, symlink/magiclink/mount denial, hardlink denial, O_PATH preflight, regular UTF-8 file enforcement, size/digest checks, and replay-safe authorization.
- Independent multi-agent review found and drove fixes for optional budget fields, spoofable event producers, invalid tool/event ordering, hardlink aliasing, data-class escape after reads, resettable ledgers, byte-reservation races, and broker close/FD reuse.
- Full suite now passes 86 tests; `compileall`, canonical validation, projection drift check, doctor, and `git diff --check` are green.
- Proof boundary remains explicit: no model adapter, OS egress/credential isolation, durable audit/state, signed observation/snapshot attestation, or Windows/macOS broker is claimed.

## [2026-07-15] implementation | M2 runtime contract foundation

- Added the separate `runtime.ai.ecosystem/v1alpha1` contract namespace and schemas for run requests, immutable plans, tool requests, policy decisions, sanitized events, artifacts, typed errors, and observed adapter capabilities.
- Added a strict broker-owned `repository.read` argument contract and sanitized runtime validation that never echoes offending untrusted values.
- Required exact identity and observed-capability references before any deployment can be enabled; placeholder DGX/cloud deployments remain disabled.
- Strengthened logical-role validation for zone, data-class intersection, and artifact-trust compatibility; removed the unverified DGX candidate from the `review.private` role.
- Documented normative D/A/Z/P semantics, immutable policy binding, M2 proof limits, and the continued absence of a runtime PEP/broker.
- Added 13 runtime contract tests and 2 canonical cross-contract tests; full validation, projection drift check, and legacy tests remain green.

## [2026-07-15] inventory | ai-legal-claude upstream snapshot

- Cloned `zubair-trabzada/ai-legal-claude` to `/home/snow/projects/ai-legal-claude` at commit `19ece98df260c4c645bdd750f6e2eb48af2bd6c4`.
- Downloaded and statically reviewed source only; no global Claude skills/agents, Python dependencies, model calls, or legal-document processing were installed or executed.
- Classified the repository as a Claude-specific prompt/checklist corpus, not a legal model, compliance authority, trusted skill package, or active deployment.
- Recorded missing skill/agent frontmatter, the broken PDF interface contract, unsafe installer/uninstaller ownership, absent license/tests/evaluations, confidentiality and prompt-injection risks, and legal overclaims.
- Preserved the useful clause taxonomy, workflow decomposition, report patterns, and a gated vendor-neutral adoption path.

## [2026-07-15] inventory | NVIDIA NeMo labs-molt upstream snapshot

- Cloned `NVIDIA-NeMo/labs-molt` to `/home/snow/projects/labs-molt` at commit `a016f4eeb71d024a1bfb11f921d5cf2c415aaa00` (`version.txt` 0.1.2).
- Downloaded and reviewed source and Git history only; no model weights, datasets, dependencies, containers, Ray services, vLLM engines, or GPU workloads were installed or executed.
- Verified Python compilation and shell-script syntax; inventoried 19 unit-test files with 127 test functions without claiming full GPU validation.
- Classified Molt as an external experimental training/evaluation node, not the vendor-neutral ecosystem core or an active deployment.
- Recorded its nested agent/learning loops, token-exact trajectory contract, async training strengths, maturity limits, hardware assumptions, supply-chain risks, and gated promotion path.

## [2026-07-15] research | Loop and Harness article verification

- Moved the supplied Markdown from Downloads into `docs/research/sources/` unchanged and recorded SHA-256 provenance.
- Inspected the complete text and all five linked images; confirmed that promised configuration blocks are absent from the archive.
- Verified product claims against current Claude Code documentation, the official MCP specification, Anthropic engineering sources, and arXiv:2606.10209.
- Accepted the harness/loop separation and context/verification/state principles; rejected the seven-file layout as a universal contract.
- Recorded corrections for settings precedence, `.mcp.json`, auto-memory, hooks, reviewer independence, benchmark scope, and indefinite loops.

## [2026-07-15] inventory | OpenResearcher upstream snapshot

- Cloned `TIGER-AI-Lab/OpenResearcher` to `/home/snow/projects/OpenResearcher` at commit `785fd6ba5fcbc068daa4a2f07bbe0964f2983c86`.
- Downloaded source and Git history only; no model weights, trajectories, corpus, embeddings, or benchmark datasets.
- Classified it as an external experimental research node, not an ecosystem core or active deployment.
- Recorded useful patterns, evidence limitations, security boundaries, and a gated future promotion path.

## [2026-07-14] docs | Loop engineering contract

- Distinguished execution, automation, and learning loops.
- Defined the bounded LoopDefinition contract, independent gate, state trust layers, budgets, hard stops, approval, and audit requirements.
- Added L0–L5 maturity levels and fail-closed promotion rules.
- Selected `wiki-health-check` as the first L2 observe/report-only candidate; kept `ml-autoresearch` second behind experiment and DGX resource safeguards.
- Recorded that candidates are not runtime services until M2–M4 enforcement and evaluation boundaries exist.

## [2026-07-14] implementation | M1 contracts/compiler foundation

- Added `ai.ecosystem/v1alpha1` canonical `.ai/` contracts and JSON Schemas.
- Implemented `eco init/validate/audit/diff/render/doctor/lock/uninstall`.
- Added safe projection ownership, explicit adopt/force, backups, drift check, and rollback-aware uninstall.
- Added sanitized secret-reference validation, cross-contract checks, unit tests, and CI.
- Reframed LiteLLM/DGX as optional adapters/profiles; central service and multi-agent runtime remain deferred.
- M2 read-only PEP/broker is the next milestone; no production-enforcement claim is made.

## [2026-07-14] chore | Ініціалізація екосистеми (Phase 0)

- Створено hub-репо: AGENTS.md (конституція), MAP.md (карта вузлів), каркаси skills/ mcp/ agents/ loops/ wiki/
- Рішення: хаб — окремий репо; dgx_spark лишається вузлом «машина DGX»
- Кандидати перших loops: wiki-health-check (🟢), ml-autoresearch (🟢)
