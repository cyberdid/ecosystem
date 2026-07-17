# M6 universal functional orchestration

**Status:** M6.0 architecture; implementation evidence is required per slice  
**Updated:** 2026-07-17  
**Target release:** `0.8.0`

## Outcome

M6 turns the existing policy, evidence, broker, artifact, recovery and team-authority
foundation into a useful vendor-neutral work system. It does not replace M1–M5 and
does not make a model, skill or agent authoritative. It adds an orchestration plane
whose work is constrained by those earlier layers.

The first executable profile is a manual, offline, read-only `source-review`:

```text
bounded local SourceBundle
        │
        ▼
Planner → Analyst → Verifier → Synthesizer → Reviewer
                                      ▲             │
                                      └ one revision┘
        │
        ▼
report + claim/evidence graph + typed handoffs + truthful terminal result
```

The useful product is not the number of agents. It is the reproducible composition:
the same goal, contracts, source bytes, role definitions, routes, budgets, artifacts
and gates can run through local NIM/Ollama, an approved cloud endpoint, or another
conformant adapter without embedding vendor-specific authority in the workflow.

## Re-sequenced roadmap

The old roadmap called enterprise/network authority and native backends M6. Those
items remain valid but move unchanged to M7. Functional orchestration is now M6
because the system already has strong enforcement but lacks daily-use skills,
general loops, role routing, memory and agent-team execution.

This is a priority change, not a security downgrade:

- M1 canonical configuration and deterministic projections remain authoritative;
- M2 read-only policy, evidence, budget and broker boundaries remain mandatory;
- M3 controlled writes remain separate and are not granted to `source-review`;
- M4 evaluation and truthful promotion semantics remain mandatory;
- M5 team authority remains narrowing-only and is not silently extended to new
  action/resource semantics;
- PostgreSQL, SSO, KMS/HSM, HA, remote consensus and native backend parity are
  postponed to M7, not claimed by M6.

## Architectural rules

1. **One canonical definition, many projections.** Skills, loops, roles and teams
   are authored once, locked by digest and projected only into formats a harness
   can honestly support.
2. **Content cannot grant authority.** Sources, model output, prompts, skills,
   memories and handoffs are untrusted data. They can propose; policy decides.
3. **Roles are logical contracts.** Code asks for `eco-researcher` or
   `eco-grader`, not Claude, Gemini, Codex, NIM or a model name.
4. **Routes are decisions, not preferences.** Eligibility is the intersection of
   policy, data class, zone, observed capabilities, context, cost, deadline and
   current evidence. A denial never triggers a hidden provider switch.
5. **Loops are bounded state machines.** Every loop has an immutable objective,
   gate, budgets, retry classes, no-progress rule, hard stop and terminal outcome.
6. **Teams are exact DAGs.** Delegation narrows capabilities and budgets. Typed
   handoffs replace shared hidden conversation state.
7. **Memory is evidence, never permission.** Persistent context retains source,
   data class, trust, namespace, supersession and expiry. Repetition does not
   promote truth.
8. **The control plane is content-free.** Raw source, prompt and model output live
   only in authorized private artifacts. Journals expose digests, bounded IDs,
   reason codes and metrics.
9. **Ambiguous external effects are not retried.** Once adapter transport may have
   started, recovery stops conservatively unless an authenticated provider result
   is available.
10. **Completion is independently checked.** A model cannot mark its own output
    accepted, verified or promoted.

## Additive contract plane

M6 uses a separate registry:

```text
apiVersion: orchestration.ai.ecosystem/v1alpha1
contractProfile: orchestration-contracts-v1alpha1
```

The existing runtime schema bundle remains byte-for-byte unchanged with digest:

```text
d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d
```

`eco_orchestration` may depend on public `eco_runtime` APIs. `eco_runtime` must not
import orchestration. The CLI is the composition root. After the first `0.8.0`
release, semantic changes to the v1alpha1 schemas require a new profile/version and
an explicit migration rather than reinterpretation.

### Definition records

| Kind | Purpose | Cannot do |
|---|---|---|
| `RoleProfile` | Bind role revision, instruction artifact, logical model role, accepted inputs, output schema and ceilings | Grant policy, tools or deployment access |
| `TeamManifest` | Bind the exact role DAG, handoff edges, separation rules and aggregate ceiling | Spawn undeclared roles or widen child authority |
| `LoopDefinition` | Bind trigger, state graph, gates, attempt limits, revision edge and hard stops | Change objective/gate during execution |

### Runtime and evidence records

| Kind | Purpose |
|---|---|
| `SourceBundle` | Bind accepted source artifacts, content descriptors, classification, trust and aggregate size without host paths |
| `TeamRunRequest` | Bind task artifact, source bundle, explicit deployment pins and requested budget |
| `TeamRunPlan` | Immutable parent plan for profiles, DAG, stages, routes, budget allocation, terminal rules and context profile |
| `RouteDecision` | Bind one role attempt to selected/denied deployment and exact child runtime route; no fallback in M6.1 |
| `RoleAttemptResult` | Bind one attempt to child plan, policy decision, model request/result, artifacts, usage and safe outcome |
| `HandoffRecord` | Carry completed task, artifact refs, claims, uncertainties, failed approaches, next role and budget snapshot |
| `ClaimRecord` | Bind a proposed statement artifact to its author and exact source bundle; it has no mutable verified flag |
| `EvidenceRecord` | Bind a claim to an exact source artifact and bounded locator with supports/contradicts/context relation |
| `VerificationRecord` | Record verifier verdict over immutable claim/evidence digests |
| `ReviewRecord` | Record reviewer verdict and issue references over an exact report; it is semantic evidence, not authority |
| `TeamRunResult` | Record exactly one truthful terminal result and all result/evidence/usage heads |
| `OrchestrationEvent` | Content-free authenticated meta-run event for recovery and replay |

All records use closed JSON Schema 2020-12 objects, canonical UTC timestamps,
bounded strings/arrays/integers, full SHA-256 digests, integer microUSD and
allowlisted reason codes. Text payloads are private CAS artifacts referenced by
digest; they are not embedded in audit records.

## Mandatory model-execution bridge

The existing `OpenAICompatibleAdapter` is a one-shot transport adapter. Directly
calling it from a team would bypass durable model budget, replay protection and
crash recovery. M6.1 therefore requires this governed path before any team runner:

```text
exact child RunPlan
  → PolicyEngine.authorize_model
  → single-use PolicyDecision
  → durable PREPARE + budget reservation
  → adapter-start fence
  → broker-owned typed-message invocation
  → output to private CAS
  → validate ModelResult and usage
  → atomic COMPLETE or sanitized FAIL
```

The authorization binds active plan, project/config/schema profile, deployment and
identity, endpoint binding, current observed capabilities, input artifact, data
class, limits, timeout, deadline and `fallbackPolicy=none`.

Model request count is spent before egress. Actual output bytes/tokens/cost settle
once after a valid result. A crash before `started` may resume. `started` without an
authenticated result is `ambiguous` and is never automatically sent again. A
completed replay makes zero provider calls and adds zero cost.

Typed instruction/source separation is also mandatory. A conformant invocation has
separate system/role instructions, structured runtime state and untrusted source
messages. XML/Markdown delimiters inside one opaque `input_text` are not a security
boundary. Tools are disabled for every M6.1 request.

## Source-bundle boundary

The path-bearing import manifest is operator input and does not enter SQLite. The
importer accepts only canonical repository-relative regular files with declared
source ID, SHA-256, byte length, media type and data class. Initial media types are:

- `text/plain`;
- `text/markdown`;
- `application/json`.

The importer enforces per-file, file-count and aggregate bounds; UTF-8 without NUL;
NFC canonical paths; no absolute/traversal/backslash/percent/control paths; no
duplicate or normalization-colliding IDs; no symlink, hardlink, FIFO, socket,
device, directory or recursive import. It rechecks descriptor identity and bytes
across read and CAS installation to detect source substitution.

A Git commit is provenance, not execution permission. External repository sources
must additionally bind canonical remote, commit, tree and selected file digests.
Hooks, dependencies, notebooks, containers and repository code are never executed
during ingestion.

## Fixed `source-review` profile

### Roles and attempts

| Stage | Input view | Output responsibility | Max attempts |
|---|---|---|---:|
| Planner | Task + source descriptors | Scope, questions, coverage plan | 1 |
| Analyst | Plan + exact sources | Claims and candidate evidence | 1 |
| Verifier | Sources + claims/evidence | Supported/contradicted/unresolved verdicts | 1 |
| Synthesizer | Verified/unresolved graph + sources | Report with explicit uncertainty | 2 |
| Reviewer | Sources + verification graph + report | `accept`, `revise` or `reject/incomplete` | 2 |

Normal acceptance uses five calls. One reviewer-requested revision permits exactly
one additional synthesizer call and one final reviewer call, for a hard maximum of
seven. Repeated report digest, repeated issue set, second `revise`, deadline or
budget exhaustion terminates truthfully as `incomplete` or `exhausted`, never
success.

M6.1 uses one operator-pinned `local-loopback` deployment for all roles under an
explicit zero-cost profile: `maxCostMicrousd == 0`, every reservation is zero and
no cloud-priced endpoint is eligible. That proves role isolation and team
orchestration, not independent models or provider billing. Per-role multi-model
routing, trusted price catalogs and explicit fallback are M6.4.

### Context assembly

Every role receives a newly assembled, bounded CAS artifact rather than the prior
agent's full conversation or chain of thought:

- planner: task artifact and source descriptors;
- analyst: frozen plan and source bytes;
- verifier: source bytes plus claim/evidence artifacts;
- synthesizer: verification graph, unresolved issues and exact sources;
- reviewer: frozen rubric, source bundle, verification graph and report.

Handoffs contain work product, artifact references, uncertainties, open questions,
failed approaches and the next action. They never contain hidden reasoning and can
never alter role, route, policy, budget or gate.

### Terminal meaning

`success` means the fixed structural and evidence-integrity gate accepted the exact
report. It does not mean universal factual truth. Other valid outcomes are
`incomplete`, `denied`, `exhausted`, `failed` and `cancelled`. The orchestration
result keeps this distinction even when mapped onto older runtime terminal states.

The hard gate verifies schemas, DAG/order, namespace and reference integrity,
source locators, claim coverage, unsupported-claim visibility, route currentness,
artifact availability, total accounting, reviewer separation and revision limits.
LLM reviewer opinion alone is never the hard gate.

### Operator composition and invocation

The production surface is `eco team run source-review`. It has no scripted or
fake production mode. `--check` validates the same package profiles, canonical
configuration, external state locations, exact loopback endpoint and signed
adapter-conformance authority without creating the database, CAS or provider
traffic.

```bash
eco --repo /absolute/project team run source-review \
  --manifest sources/source-review.json \
  --database /private/runtime/source-review.sqlite3 \
  --artifact-store /private/runtime/source-review-cas \
  --run-id review-20260717-01 \
  --store-id laptop-local-review \
  --created-at 2026-07-17T12:00:00Z \
  --deadline-at 2026-07-17T12:30:00Z \
  --check --json
```

Remove `--check` only after the preflight is ready. The database and CAS must be
private absolute locations outside the governed repository. HMAC and CAS proof
keys come from `ECO_SOURCE_REVIEW_HMAC_KEY` and
`ECO_SOURCE_REVIEW_PROOF_KEY` by default; only their environment-variable names
are CLI inputs. The selected deployment must be the sole enabled deployment,
use provider `local`, adapter `openai-compatible`, adapter version
`openai-compatible-v1`, the exact `review.private` logical role and a literal
loopback `/v1/chat/completions` URL resolved from its `env:` endpoint reference.

`trust.conformance.requiredObservations` must reference an external canonical
HMAC evidence envelope for the same deployment and a trusted suite. Both
`model.text` and `model.structured-output`, including the
`structured-output-strict` probe, must pass. Endpoint and orchestration route
authority end at the earliest of the declared deadline, signed observation
expiry and evidence-envelope expiry. The run is at most one hour and its stable
creation time must be current; reusing the same run/store identifiers, times,
database and CAS makes terminal model calls replay without provider egress.

The command emits only the content-free `TeamRunResult` graph and final report
artifact binding. It does not print or export report/source/provider bytes. It
does not use provider credentials, proxies, redirects, tools, source network or
workspace writes. A successful structural/evidence gate is not a universal
truth claim, prompt-injection immunity, independent-model consensus or proof of
cloud/provider equivalence.

## M6 delivery slices

| Slice | Functional deliverable | Exit signal |
|---|---|---|
| M6.0 | ADR-027/028, architecture, research synthesis, threat model and test plan | Scope and no-claims frozen; baseline 474 remains green |
| M6.1a | Durable governed typed model invocation | Policy→PREPARE→adapter→CAS→COMPLETE, no-retry recovery tests |
| M6.1b | Fixed offline `source-review` vertical slice | Installed CLI produces report/evidence/handoffs with zero tools/source-network/writes |
| M6.2 | Canonical skills and harness sync | Lock, provenance, deterministic projections, drift/rollback/uninstall tests |
| M6.3 | Generic bounded loop engine | Closed state machine, retries, hard stops, recovery and evaluation separation |
| M6.4 | Model roles and policy router | Deterministic eligibility/explain, fresh decisions, explicit bounded fallback |
| M6.5 | [Private context and memory graph](private-context-memory.md) | Namespaced CAS-bound provenance, TTL/supersession/conflict, reversible compaction, no trust promotion |
| M6.6 | General agent-team orchestration | Exact DAG, narrowed delegation, parallel budget/task claims, truthful partial failure |
| M6.7 | Governed live research tools | Allowlisted brokered search/fetch with provenance, injection isolation and egress policy |
| M6.8 | Conformance and `0.8.0` | Full regression, installed-wheel smoke, cross-platform contracts and explicit non-claims |

Enterprise/network authority, remote control planes, SSO and native platform
security backends become M7. Training/learning nodes such as MOLT remain optional
M8-style experimental capabilities and never define the orchestration core.

## M6.3 generic bounded-loop runtime

The additive `eco_loops` package enforces deterministic `no-effect` and
`report-only` loops. Frozen objective/gate digests, separate actor and gate
callables, closed transitions, conservative attempt/iteration/deadline/token/cost/
storage reservations, retry allowlists, repeated-progress stops, cancellation and
the kill switch are runtime checks rather than prompt conventions.

The optional single-host SQLite journal atomically binds content-free events and
checkpoints, refuses inconsistent replay and never repeats an ambiguous started
attempt. `source-review-outline/v1` is deliberately non-executable; the fixed M6.1
runner remains authoritative. `wiki-health-check-compat/v1` delegates exactly once
to the existing M4 workflow. M6.3 claims no scheduling, arbitrary code execution,
new write authority, authenticated audit anchor or distributed durability.

## External systems: adopt patterns, not authority

| Source | Useful pattern | M6 placement | What is not imported |
|---|---|---|---|
| OpenResearcher | Research task decomposition, trajectory/evaluation ideas | Role and evaluation fixtures | Training runtime, dataset or unrestricted search authority |
| OpenScience | Scientist workbench UX and methodology packaging | Future research profile/loop inspiration | Mutable skill catalog, cloud coupling, unsafe execution defaults |
| NVIDIA MOLT | Typed trajectories, async training/evaluation loops | Optional later training node | Orchestration core, implicit GPU requirement, unreviewed supply chain |
| Multi-model team article | Role aliases, typed handoffs, checker separation | M6 role/team/context contracts | Vendor marketing claims or prompt-only security |

## Evidence required for completion

M6.1 requires deterministic scripted-adapter CI, adversarial source/injection tests,
budget and crash fault injection, repository byte/mtime identity, leak-sentinel scans,
installed-wheel import/smoke, old schema-digest pinning, full M1–M5 regression and
canonical validation/render/doctor gates. Optional live local NIM/OpenAI-compatible
evidence is additive and must use externally provisioned current observation data.

Passing fixtures proves only the bounded offline profile. It does not prove arbitrary
model truth, prompt-injection immunity, provider equivalence, safe third-party code
execution, model independence, native non-Linux isolation or production readiness.

## Related documents

- [M6 threat model](m6-functional-orchestration-threat-model.md)
- [M6.0 research and implementation plan](../research/2026-07-17-m6.0-functional-orchestration-plan.md)
- [Runtime contracts](runtime-contracts.md)
- [Team authority](team-authority.md)
- [Loop engineering](../../wiki/loops.md)
- [Decision register](../decisions/README.md)
