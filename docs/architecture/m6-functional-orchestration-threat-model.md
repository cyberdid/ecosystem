# M6 functional orchestration threat model

**Status:** M6.0 design and acceptance boundary; not an implementation or promotion claim  
**Updated:** 2026-07-17  
**Target slice:** M6.1 offline `source-review`

## Purpose

M6 adds useful orchestration above the existing M1–M5 policy, broker, artifact,
runtime, approval and team-authority foundations. Its first vertical slice is a
manual, bounded, read-only review of a locally supplied source bundle by the
fixed role sequence:

```text
Planner → Analyst → Verifier → Synthesizer → Reviewer
```

This document defines the threats, invariants, negative tests and evidence that
must exist before that workflow may be called an executable M6.1 capability. It
also records the adversarial gates expected for the later M6.2–M6.6 slices.

The central security rule is unchanged: a model, source, prompt, skill, agent or
client can propose data, but only the trusted runtime and its external policy
boundaries may grant authority or record a terminal decision.

## Exact baseline constraints

M6 starts from repository revision `0966d087811aa45c71c1b88599c9d3ab6ee19393`
and package version `0.7.0`. Hosted run
[`29519155069`](https://github.com/Pylypko1021/ecosystem/actions/runs/29519155069)
passed the existing Linux regression and offline wheel smoke plus the focused
macOS and Windows contract suites. That evidence is a regression baseline; it
does not prove any M6 functionality.

The baseline has deliberately narrower contracts that M6 must not silently
reinterpret:

- `RunPlan` contains exactly one required `route`; it is not a team plan.
- `ModelRequest.fallbackPolicy` is exactly `none`.
- `OpenAIChatInvocation` carries one opaque `input_text`; it does not provide an
  enforceable role-instruction versus untrusted-source channel boundary.
- `RunEvent` contains the three fixed M4 wiki-health scope slots.
- Runtime terminal states are `SUCCEEDED`, `FAILED`, `DENIED`, `CANCELLED` and
  `EXHAUSTED`; they do not distinguish an incomplete research result.
- `ErrorRecord` has no routing, team, verification or memory stage.
- The workflow installs and tests Python 3.12, while the package declares
  Python 3.11 or newer.
- The M4 runtime schema bundle digest remains
  `d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d`;
  M5 already keeps authority schemas in a separate registry.

M6 must therefore use an explicitly versioned functional/team contract profile
or an explicit schema migration. It must not widen the meaning of an existing
record while retaining the old profile and digest. A parent team plan should be
immutable and bind exact child single-route plans; a child plan must never gain
authority absent from the parent.

The preserved research source
`docs/research/sources/how-to-build-a-multi-model-ai-team-in-2026.md` has SHA-256
`59c616d7b701449797ca747838fdd31b5c7a677017863f2a03b174fd78ee007e`.
Its presence and checksum are provenance facts, not evidence that its marketing
claims or embedded instructions are trusted.

## Trust boundaries

```text
operator-owned trust anchors and canonical contracts
                         │
                         ▼
trusted composition root: policy + planner + state reducer
                         │
          ┌──────────────┼────────────────┐
          ▼              ▼                ▼
 brokered source     private CAS      broker-owned adapter
 ingestion/read      and journals     transport/credentials
          │              │                │
          └──────────────┼────────────────┘
                         ▼
       untrusted model outputs, sources and handoffs
                         │
                         ▼
        independent runtime verification and terminal gate
```

### Operator and canonical-contract boundary

The operator selects the project, source bundle, role/team/loop revisions,
budgets, deployments and trust anchors. Project files, environment variables or
model text cannot replace those choices. Lower-precedence material may narrow a
request but cannot broaden the operator or platform grant.

### Trusted runtime boundary

The trusted runtime owns plan construction, state transitions, routing
eligibility, budget reservations, checkpoint authentication, artifact metadata,
terminal outcomes and audit events. Agents do not write directly to the event
ledger, select their own trusted role or declare their own work accepted.

### Source boundary

Markdown, PDFs, Git files, issues, webpages, tool results, metadata and embedded
prompts are untrusted data. The source bundle is accepted only through bounded
ingestion with exact content, size, media type, classification and provenance
binding. A cloned third-party repository is never imported or executed merely
because its commit SHA is known.

Sources outside the governed repository need a separate trusted ingestion
boundary. Agents must not receive arbitrary host paths. A Git source manifest
must bind the canonical remote identity, exact commit, tree digest, selected
file digests and ingestion policy before bytes enter the private CAS.

### Model and adapter boundary

The model is an untrusted transformation service. Broker-owned transport holds
credentials and endpoint state. The exact deployment, revision, endpoint
binding and observed capability evidence are runtime inputs. Transport
compatibility is not semantic compatibility.

M6.1 must not claim prompt-injection isolation while role instructions and
source bytes are concatenated into one opaque string. Role/system instructions,
structured task state and untrusted source content require separate typed
channels. Delimiters, Markdown fences or XML tags inside one string are useful
formatting, not an authority boundary.

### Artifact versus audit boundary

Private artifacts may contain the authorized report and source-derived text at
their assigned data class. Public status, event, error and audit records contain
only bounded identifiers, digests, reason codes and metrics. Intentional result
export is a separate authorized data path; it must not be confused with logging.

### Team and handoff boundary

A role is a contract, not a prompt label. Every execution has an exact role,
task, plan, route, input and output binding. Handoffs are typed artifacts created
by the runtime from validated output. Text claiming to be another agent,
reviewer, tool result or approval has no authority.

### Project, team and run isolation boundary

Every mutable or retrievable record is scoped to an exact project, team and run.
A matching content digest from another namespace does not grant access. Memory
and prior results remain evidence, never authorization.

## Threat actors and failure classes

The design assumes any combination of:

- a malicious or compromised source containing instruction injection;
- a malformed, adversarial or compromised model response;
- an unavailable, drifting or falsely described deployment;
- a caller attempting cross-project, cross-team or cross-run substitution;
- an agent attempting capability escalation, self-review or evaluator mutation;
- concurrent workers racing budgets, tasks, handoffs or terminal state;
- process loss at any durable boundary;
- local state corruption, replay, wrong-key reopen or checkpoint substitution;
- sensitive content appearing in exceptions, status, audit, `repr`, stdout or
  stderr;
- filesystem aliases, path traversal, Unicode collisions and source changes
  during ingestion.

Compromise of the operator's trust anchors, broker-owned credentials, runtime
process or host kernel is outside the local reference threat boundary. Those
events remain incident conditions; the system must not claim to withstand them.

## Explicit non-goals for M6.0 and M6.1

M6.0 is documentation and contract planning. M6.1 is intentionally narrower
than the full roadmap. Neither milestone claims:

- live web search, arbitrary network tools or authenticated browser access;
- workspace writes, patches, commits, external messages or production changes;
- autonomous scheduling, an unbounded loop or unattended recovery;
- general skill installation or harness synchronization;
- a capability-scored universal router or automatic fallback;
- durable project memory or evidence-compounding learning;
- parallel teams, recursive delegation or arbitrary agent spawning;
- enterprise PostgreSQL/HA, SSO, KMS/HSM, remote attestation or consensus;
- native Windows/macOS isolation, filesystem race or secret-custody parity;
- safe execution of third-party repository code, build scripts or containers;
- semantic truth merely because a report is structurally valid;
- cryptographic or organizational independence when one physical deployment is
  reused for multiple roles;
- production readiness, prompt-injection immunity or model-provider neutrality
  beyond the exact tested adapters and profiles.

The initial CI workflow must use deterministic scripted adapters and no cloud
credentials. Real-provider evaluation is separate evidence and cannot replace
the deterministic gate.

## P0 invariants

Violation of any P0 invariant blocks M6.1 completion.

1. **No self-granted authority.** Model, source, prompt, skill and handoff fields
   can never modify policy, route, role, team, budget, gate or terminal state.
2. **Exact immutable plan.** The parent plan binds the role DAG, task, inputs,
   gates, budgets and exact child plans by digest. Mutation creates a new plan
   and requires new authority.
3. **Capability narrowing.** A child role receives an exact subset of the parent
   capabilities, data classes, tools, routes, time and budget.
4. **Default deny.** Missing, unknown, ambiguous, stale, malformed or conflicting
   input denies or fails before the affected invocation.
5. **Policy denial is terminal for the action.** No provider, model, tool or role
   switch may bypass a denial.
6. **No silent fallback.** M6.1 retains `fallbackPolicy=none`. Later fallback
   requires a fresh route decision for an explicitly retryable failure.
7. **Typed untrusted-content separation.** Role instructions and source bytes
   occupy different typed channels. Retrieved or remembered content never
   becomes an instruction channel.
8. **Untrusted output.** Every model result begins at `P0` and cannot mark its own
   claims verified, its task complete or its review accepted.
9. **Exact source integrity.** Every accepted byte is bound to a source-bundle
   entry, content digest, byte length, media type, data class and provenance.
10. **Bounded execution.** Parent and child limits cover attempts, model calls,
    input/output bytes, tokens, cost and one persistent deadline. Reservation
    and consumption are atomic across concurrent workers.
11. **Truthful terminal semantics.** Exactly one terminal outcome is recorded.
    `incomplete`, `denied`, `exhausted`, `failed` and `cancelled` are never
    reported as success. If incomplete is a result status over a legacy runtime
    terminal state, that distinction must be explicit and machine-readable.
12. **Independent gate ownership.** The runtime owns the gate. A reviewer cannot
    approve its own produced artifact, and the actor cannot change the rubric,
    threshold or held-out tests.
13. **Conservative recovery.** Pre-start work may be retried. An authenticated
    `adapter.started` without a terminal outcome is ambiguous and is not invoked
    again automatically.
14. **No duplicate accounting or effects.** Replays restore authenticated
    metadata without another provider call, cost charge, task claim or artifact
    publication.
15. **Content-free control plane.** Audit, error, status and route-explanation
    records do not contain raw source, prompt, response, path, endpoint, secret
    or exception text.
16. **Namespace isolation.** Project, team and run bindings are checked at every
    read, handoff, route, checkpoint and artifact boundary.
17. **No direct egress.** Agents have no provider credentials or direct network
    access. Only broker-owned adapters can perform the exact authorized model
    request.
18. **Read-only vertical slice.** M6.1 creates no workspace-write, shell,
    external-write, scheduling or memory-promotion authority.

## M6.1 `source-review` acceptance gates

### Gate A — contract and plan integrity

- A versioned `SourceBundle`, role/team definition, team run plan, handoff and
  result contract exists with closed schemas and semantic validation.
- The fixed DAG is acyclic, contains each required role once and has no implicit
  role, edge, inheritance, wildcard or default administrator.
- The parent plan binds exact source, role, route, policy, gate and child-plan
  digests plus one deadline and aggregate budget.
- Unknown fields, role reordering, duplicated roles, graph cycles, missing
  gates, project substitution and plan mutation fail before model invocation.
- Legacy M1–M5 records retain their old meaning and regression evidence.

### Gate B — source-bundle integrity

- Ingestion accepts only allowlisted regular-file media types and exact bounded
  bytes. File count, total bytes, per-entry bytes and UTF-8 policy are explicit.
- Absolute paths, traversal, backslashes, percent escapes, control characters,
  normalization collisions, duplicate names, symlinks, hardlinks, FIFOs,
  devices and sockets fail closed.
- Source changes between manifest inspection, open and CAS installation are
  detected. A partial bundle is never published as accepted.
- External Git evidence binds remote, commit, tree and selected files; no hook,
  checkout script, package manager, Python module or container is executed.
- Wrong, missing, stale or lower-trust provenance prevents the corresponding
  source from entering the run.

### Gate C — model channel and route safety

- Role instructions, task state and untrusted sources are represented as
  separate typed messages; source bytes cannot create system/tool messages.
- Tools are disabled for every M6.1 model request.
- Each child request is bound to one exact eligible deployment, revision,
  endpoint binding and fresh capability evidence.
- Disabled, stale, unavailable, mismatched, context-insufficient or
  data-ineligible deployments return a typed denial or failure.
- Timeout, transport error, wrong reported model, malformed response, excessive
  output and excessive usage stop the role without invoking another candidate.
- Provider credentials, endpoint URLs and raw provider IDs do not enter the
  agent input or public control-plane output.

### Gate D — role execution and handoffs

- The runtime starts a role only after all exact predecessor handoffs are
  present, valid and bound to the same project/team/run/plan.
- A handoff records typed task outcome, artifacts, claims, evidence references,
  uncertainty, open questions, budget use and next-role identity.
- Role text cannot impersonate a predecessor, tool, verifier, reviewer or
  operator. Forged and replayed handoffs fail closed.
- Missing or failed required roles prevent downstream success. The synthesizer
  cannot hide a child denial or failure.
- M6.1 permits at most one reviewer-requested revision cycle.

### Gate E — claims, evidence and review

- Every report claim has a typed state and zero or more exact source/evidence
  references. Unsupported claims cannot be marked verified.
- The verifier cannot manufacture source authority or change source bytes.
- The reviewer receives the exact synthesis artifact and frozen rubric, cannot
  rewrite the evidence graph and cannot be the producer of the reviewed
  artifact.
- Conflicting evidence remains explicit. Insufficient evidence produces an
  `incomplete` result rather than invented consensus.
- Reusing one deployment for several roles is recorded. It may be a separate
  invocation but cannot satisfy a gate that requires independent model,
  provider, organization or evidence provenance.

### Gate F — budget and deadline

- Aggregate and per-child reservations occur before invocation and serialize
  across workers.
- Provider usage is validated and accounted once before its result may support
  a successful terminal record.
- A response exceeding its reservation is retained only as failed private
  evidence; it cannot be accepted or trigger another attempt.
- Deadline, cancellation and current policy are checked before invocation,
  after invocation and before finalization.
- Cost enforcement either uses an exact trusted pricing snapshot or M6.1 is
  explicitly restricted to zero-cost deterministic/local profiles. Token counts
  alone are not a cost proof.

### Gate G — recovery and replay

- Durable records authenticate the exact plan, state projection, event head,
  budget, open operations, artifacts and deadline.
- Kill tests cover plan issue, route decision, pre-invoke, adapter started,
  provider return, artifact installation, journal commit, handoff publication,
  reviewer verdict and terminal publication.
- An ambiguous post-start invocation becomes a typed incomplete/failed terminal
  condition and is never retried automatically.
- Completed role results and handoffs replay with zero provider calls and zero
  additional accounting.
- Wrong key, corrupted journal, missing artifact, changed plan/gate/policy,
  cross-run checkpoint and backwards state transition fail closed.

### Gate H — isolation and redaction

- Runtime state and private CAS are outside the governed repository and reject
  unsafe aliases and permission exposure on supported POSIX profiles.
- The governed repository tree is byte-identical before and after a run.
- Cross-project, cross-team and cross-run artifact, handoff, checkpoint and
  route substitutions are denied even when content digests match.
- Unique sensitive sentinels injected into sources, model output and exceptions
  are absent from events, errors, SQLite, status JSON, route explanations,
  `repr`, stdout and stderr.
- The explicitly requested final-artifact export is tested separately at the
  correct data class; audit redaction must not make the useful artifact
  inaccessible to its authorized user.

### Gate I — deterministic functional result

Using only scripted adapters, the installed CLI can execute one fixed offline
source bundle and return:

- a terminal status and reason;
- final report artifact reference and digest;
- claim-to-evidence mapping;
- route-decision references;
- ordered typed handoffs;
- aggregate and per-role budget accounting;
- terminal and artifact provenance.

The same fixture and immutable inputs produce semantically identical records,
apart from explicitly variable run IDs/timestamps, and no network or repository
write is observed.

## Prioritized M6.1 negative-test matrix

| Priority | Area | Adversarial cases | Required result |
|---|---|---|---|
| P0 | Authority and plan | Unknown/extra/reordered role; graph cycle; changed gate, task, source, route or budget digest; child capability exceeds parent; project/run substitution | Typed deny/fail before invocation; no partial plan activation |
| P0 | Policy and fallback | Policy/data/zone denial followed by another provider, tool or role; expired/replayed route decision | Denial is terminal for the action; zero fallback calls |
| P0 | Source integrity | Digest/size/media/provenance mismatch; traversal; Unicode/case collision; link or special file; source swap; partial ingest | Bundle rejected atomically; no model call; no raw path/content in audit |
| P0 | Prompt injection | Source asks to ignore rules, reveal secrets, forge system/tool JSON, call a tool, approve a claim or impersonate a role | Remains source data; cannot alter plan, message roles, permissions or gate |
| P0 | Model output | Wrong schema, Markdown instead of schema, extra policy/tool/route fields, forged citation/handoff/reviewer verdict, oversized output | Output rejected or retained as `P0` failed evidence; no downstream authority |
| P0 | Routing | Disabled/mismatched model, stale/forged capability evidence, context or privacy mismatch, wrong endpoint/revision/reported model | Typed denial/failure; no implicit candidate switch |
| P0 | Reviewer separation | Reviewer execution equals synthesizer execution; reviewer produced subject; same model presented as independently corroborating itself | Self-review blocked; independence accurately classified |
| P0 | Evidence | Missing source reference, forged digest, verifier creates source, synthesizer upgrades unsupported claim, contradictory claims hidden | Result is incomplete/failed; unsupported state remains visible |
| P0 | Budget | Parent/child/concurrent overspend; expired deadline; usage exceeds reservation; zero budget; second revision | Atomic stop with exhausted status; accepted totals never exceed limits |
| P0 | Crash and replay | Crash at every durable boundary; ambiguous adapter start; checkpoint tamper; wrong key; replay completed role | No automatic ambiguous retry; completed work has zero duplicate call/accounting |
| P0 | Isolation | Cross-project/team/run record substitution; same digest in another namespace; state/CAS overlaps repository | Access denied; repository and foreign namespace unchanged |
| P0 | Redaction | Secret/path/endpoint/source sentinel in exception, provider response, source and role output | Sentinel absent from control-plane outputs and durable audit |
| P1 | Cancellation | Cancel before, during and after a role; downstream queued work | Cancellation propagates; no downstream start; one terminal record |
| P1 | Concurrency | Duplicate task claims, terminal race, shared budget race, duplicate handoff publication | At-most-once claim/publication; serial aggregate accounting |
| P1 | Partial team failure | Analyst/verifier/reviewer fails or returns incomplete | Failure cannot be hidden by synthesis; truthful terminal result |
| P1 | Progress | Repeated identical response/error or reviewer loop | Stop at configured no-progress/revision limit |

Every P0 negative test should assert all three properties:

1. the exact typed reason code or terminal status;
2. no forbidden invocation, read, write, fallback, artifact promotion or memory
   promotion occurred;
3. the error and audit surfaces do not echo the adversarial input.

## Later M6 adversarial gates

### M6.2 — skills and harness synchronization

- Discovery and synchronization never execute skill scripts, imports, hooks or
  package-manager commands.
- Every skill binds stable ID, version, source, immutable commit, content digest,
  license, capabilities, dependencies, tests and revocation state.
- Mutable branches/tags such as `main` or `latest`, redirect substitution,
  force-push mismatch, digest mismatch and version downgrade fail closed.
- A skill cannot grant itself filesystem, network, model, tool or approval
  capability through prose or manifest fields.
- Traversal, symlink escape, hardlink alias, Unicode/case-fold collision,
  duplicate ID/name and Windows reserved-name fixtures fail closed.
- Projection refuses unmanaged-file overwrite. Managed marker tamper, partial
  apply, crash, concurrent sync, rollback and uninstall are tested atomically.
- Uninstall removes only exact owned generated files. User and unrelated files
  remain byte-identical.
- Identical canonical input produces deterministic Codex, Claude, Gemini and
  generic projections plus an immutable lockfile.

### M6.3 — generic loop engine

- The state machine rejects unknown and backwards transitions and records one
  terminal outcome.
- The actor cannot change objective, gate, evaluator, threshold, held-out tests,
  budget or policy during a run.
- Policy denial is terminal. Retry applies only to an explicit retryable class
  and cannot switch provider/tool to evade policy.
- Attempt, wall-time, token, cost, storage, consecutive-failure and no-progress
  limits are independent hard stops.
- Repeated identical action/error, environment drift, current-evidence expiry,
  kill switch and operator cancellation stop the loop.
- Idempotency and ambiguity fences prevent duplicate side effects. An uncertain
  post-start effect is never replayed automatically.
- Checkpoint corruption, wrong run/project, changed plan/gate and concurrent
  resume fail closed.
- `exhausted` and `incomplete` are never promoted to success.

### M6.4 — model roles and routing

- Eligibility is the intersection of policy, data/zone/region/retention,
  declared and observed capabilities, freshness, context, reliability, budget
  and route strategy.
- Stale, replayed, forged, deployment-mismatched or self-declared benchmark
  evidence creates no eligibility.
- No candidate returns a typed denial with sanitized per-candidate reason codes.
- Candidate ordering and tie-breaking are deterministic for exact inputs.
- Fallback needs a fresh route decision, remaining budget and an explicitly
  retryable failure. Safety, data and authority denials never fallback.
- Wrong provider model, malformed usage, correlated reviewer and cost/context
  overflow cases fail closed.
- Route explanation contains bounded IDs, digests and reason codes, not endpoint,
  credentials, source content or raw provider messages.

### M6.5 — context, memory and handoffs

- Namespace and access checks prevent project/team/run leakage and honor current
  membership and revocation.
- A `P0` claim or summary cannot become verified merely by persistence,
  repetition or another model restating it.
- Data class never downgrades through summarization, compaction or handoff.
- TTL, retention, revocation, supersedes, refutes and conflict semantics are
  explicit and tested.
- Missing provenance or parent artifact makes a record ineligible for trusted
  context.
- Memory prompt injection remains untrusted data and cannot change role, policy,
  route or tool authority.
- Compaction preserves source links, uncertainty and reversibility to original
  artifacts; poisoned summaries and loss of unresolved claims are detected.
- Concurrent writers cannot lose updates, publish partial records or reuse a
  record across namespaces.
- Memory is never an authorization source.

### M6.6 — agent-team orchestration

- Team definitions are closed, exact and acyclic. Recursive spawn and implicit
  delegation are disabled unless separately bounded.
- Child capabilities, data and budgets are exact subsets of the parent.
- Impersonation, forged/cross-run handoff, duplicate claim and task replay fail
  closed.
- Reviewer and approver separation is enforced; no agent can review or approve
  its own produced artifact or authority request.
- Parallel work serializes aggregate budget, task claim, handoff and terminal
  publication.
- Child denial/failure and cancellation propagate according to the immutable
  team policy and cannot be hidden by a later role.
- Conflicting findings remain unresolved until evidence resolves them. Team
  agreement is not inferred from repeated text or a shared model deployment.
- Reviewer revision is bounded to one cycle in the first profile; exhaustion
  yields incomplete, not success.
- Silent role, model or provider substitution is forbidden.

## Fixture strategy

Use builders for canonical positive records and narrow mutations for adversarial
cases. Builders should reseal digests only when the test intends to present a
well-formed but semantically malicious record.

```text
tests/
├── m6_fixtures.py
├── fixtures/m6/
│   ├── source-bundles/
│   │   ├── minimal/
│   │   └── hostile/
│   ├── adapter-scenarios/
│   │   ├── role-valid/
│   │   ├── malformed/
│   │   ├── timeout/
│   │   ├── wrong-model/
│   │   ├── overspend/
│   │   └── injection/
│   ├── contracts/
│   │   ├── roles/
│   │   ├── teams/
│   │   ├── loops/
│   │   ├── routes/
│   │   ├── memory/
│   │   └── skills/
│   └── golden-public/
└── test_m6_*.py
```

Recommended helpers:

- `assert_code(expected, callable)`;
- `assert_no_effect(spies, before_state)`;
- `assert_no_leak(sentinels, public_surfaces)`;
- canonical record builders and digest sealers;
- deterministic clock, ID and scripted-adapter controls;
- fault injection for each durable boundary.

Symlink, hardlink, FIFO, permission, source-swap, concurrent-process and crash
fixtures must be generated at runtime. They should not be represented by
portable-looking regular files in Git. Test files should remain split by
boundary: contracts, source bundle, source review, injection, budget, recovery,
isolation, skill sync, loops, router, memory and team orchestration.

## CI strategy

Required M6 gates:

1. Preserve the full Linux regression, canonical validation, projection drift
   check, doctor and offline distribution verification.
2. Add pure M6 contract and adversarial suites to Linux, macOS and Windows.
3. Run real CAS/filesystem/process-crash/concurrency tests only on a supported
   Linux profile and state explicit non-claims for other platforms.
4. Run deterministic scripted adapters only. No external model, live web search
   or repository write is required for CI success.
5. Hash or otherwise verify the governed repository before and after the
   source-review smoke; require byte identity.
6. Scan public control-plane records, SQLite, stdout and stderr for unique leak
   sentinels. Exclude only the explicitly authorized private source/result
   artifact bytes.
7. Build the wheel, install it without index access, verify every M6 module and
   schema is present, and execute a deterministic installed-CLI source-review
   smoke with zero network.
8. Check the dependency lock without update and use a frozen resolution for the
   reproducibility job. The present range-resolved `pip install -e` alone is not
   a locked-environment proof.
9. Test Python 3.11 and 3.12 contract behavior because both are declared
   supported.
10. Treat a skipped security test as `not tested`, never as a passing security
    claim.
11. Require exact negative assertions for deny, fallback and state-transition
    branches. If coverage enforcement is introduced, prioritize complete
    coverage of authority transitions instead of relying on a global percentage.
12. Pin third-party CI actions to reviewed immutable revisions when the workflow
    is hardened for release supply-chain evidence.

## Completion and no-claim language

M6.0 is complete when this threat model, the scoped roadmap decision and M6.1
acceptance criteria are reviewed and versioned. It does not make M6.1 complete.

M6.1 may be called complete only after all P0 gates pass in source, installed
wheel and hosted CI evidence, the complete M1–M5 regression remains green and
the completion report lists exact limitations and skipped/non-applicable tests.

Passing deterministic fixtures proves the exact bounded offline profile. It
does not prove that arbitrary model output is truthful, arbitrary sources are
safe, prompt injection is solved, different providers are semantically
equivalent, one model acting in several roles is an independent team, external
Git code is safe to execute, or the system is production-ready. Broader claims
require separate contracts, threat models, conformance evidence and promotion.
