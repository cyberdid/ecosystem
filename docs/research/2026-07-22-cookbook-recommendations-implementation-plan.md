# Cookbook recommendations P1–P6 — implementation plan

**Date:** 2026-07-22
**Author:** Claude (Fable 5), Claude Code
**Status:** implementation plan (contracts-first). Candidate milestone **M8** (M7 = enterprise/native backends stays separate).
**Derives from:** [vendor cookbooks source review](2026-07-22-vendor-cookbooks-source-review.md)
**Rule:** per CONTRACTS-FIRST, each P is designed here before code; per VERIFY-DONE, each ships as a slice that passes its own gate; per "no capability without verification", nothing is marked done without an objective artifact.

---

## Why a plan and not a single commit

Fully implementing P1–P5 as production features is milestone-scale work: each needs a contract, schema, module, CLI surface, tests and a passing gate — the same rigor as M1–M6. Implementing all five hastily would violate the project's own third law. This plan turns the recommendations into verifiable slices; the slice status column tracks real progress.

## Slice ledger

| P | Capability | Primary module | Contract / gate | Status |
|---|---|---|---|---|
| P4 | Reliability-technique skills | `eco_skills` | registry entry + tests + evidence + owner + digest + sync | **implemented** (`task-decomposition`, `self-consistency-verification`) |
| P1 | General eval harness | `eco_eval` (new) | eval-file → N runs → metrics → verdict; `eco eval suite <file>` | **implemented** (9 tests; judge validation live; non-zero exit) |
| P2 | Structured-output admission | `eco_runtime.structured_admission` | model must prove valid typed output before admission | **implemented** (6 tests; deterministic core; live probe deferred) |
| P3 | Vendor-neutral reference agents | `eco_teams.reference_manifests` | evaluator-optimizer + orchestrator-workers validate through the team contract | **implemented** (5 tests; deterministic validation; live PASS deferred) |
| P5 | Cost/observability contract | `eco_telemetry` (new) | per-run/role cost record, caps, stop-on-breach, content-free | **implemented** (6 tests; fail-closed caps) |
| P6 | Compliance positioning | docs | enforcement+audit mapped to AI-governance frameworks | **done** (this plan + review) |

**Delivery note (2026-07-22).** All six recommendations are implemented at their deterministic core with passing gates (26 new tests across the four code slices). Two live-dependent boundaries remain explicitly deferred with the same dependency as the M6 five-role run: P2's live structured-output probe (driving a real model) and P3's live team PASS. Nothing live is claimed.

## P4 — Reliability-technique skills (implemented)

Adds canonical, gated skills that make **any** model more reliable, encoding OpenAI's reliability techniques as procedural knowledge. Each passes the same gate as every skill (tests, evidence, owner, digest, sync). Concrete skills:

- `task-decomposition` — split a complex task into bounded sub-tasks with explicit edges (from "split complex tasks").
- `self-consistency-verification` — sample independent attempts and require majority agreement before accepting a result (from "self-consistency" + "verifiers").

These compose with `bounded-loop-authoring` and the GSC gate. They are knowledge, not runtime — they tell an agent *how* to be reliable; the runtime still enforces the boundary.

## P1 — General eval harness (highest value; answers the enforcement question)

**Contract.** An `EvalSuite` is an immutable file binding: suite id, task list (each: prompt digest, expected-shape or ground-truth reference, grader reference), independence factor N, and pass threshold. `eco eval run <suite>` executes each task through N independent graders and emits a signed, content-free verdict with metrics — never the raw prompt/response.

**Shape** (from `claude/tool_evaluation`): eval-file → N independent agent runs → metrics → verdict. This is the concrete form of the adversarial "validate-the-judge" suite: a grader that cannot catch a deliberately broken task fails suite validation.

**Acceptance gate.** Schema-valid suite; deterministic run over fixtures; the harness itself validated against a known-good and a known-broken task (the judge is judged); no raw content in the verdict; `eco eval run` returns non-zero on fail.

**Why first.** This is the literal mechanism for "how to be sure an unknown LLM follows the concepts": run the suite against their model, get a signed verdict per boundary. It generalizes M4 promotion from one fixed loop to any capability.

## P2 — Structured-output admission

**Contract.** Extend the M2 adapter conformance suite with a structured-output probe: the deployment must return output that validates against a pinned schema, with the wire projection (drop unexpressible keywords, per the M6 dogfood `grammar_safe_response_schema` finding) but authoritative validation against the full schema. Admission fails closed if the model cannot produce valid typed output.

**Acceptance gate.** Conformance envelope records structured-output adherence; a model that emits wrapper objects/prose fails admission; existing conformance tests stay green.

## P3 — Vendor-neutral reference agents

**Contract.** Two runnable `AgentTeamManifest` references built only on M6.6 primitives (no vendor SDK): `evaluator-optimizer` (proposer role + independent grader role, loop until threshold) and `orchestrator-workers` (planner fans work to N workers, synthesizer merges). They run through policy/routing/budget/audit like any team.

**Acceptance gate.** Manifests validate; deterministic dry-run without a model; a full live PASS is explicitly deferred (owner paused live-model work) and is the same dependency as the M6 five-role PASS.

## P5 — Cost/observability contract

**Contract.** A separate telemetry record (not the audit chain) capturing per-run and per-role token/cost/time against the existing `budget.py` ledger, with explicit caps and a stop condition on cap breach. Content-free; cost only.

**Acceptance gate.** A run over budget stops fail-closed; telemetry contains no raw content; `eco` surfaces spend; caps are enforced before, not after, spend.

## P6 — Compliance positioning (doc)

The project's default-deny policy, single-use decisions, HMAC/Ed25519 audit chain, human approval and revocation already constitute an AI-governance substrate. This is mapped in the review as a differentiator over the cookbooks (Gemini's EU-AI-Act agent needs exactly this substrate). No code; positioning only.

## Sequence and dependencies

1. **P4** (done) — no dependencies.
2. **P1** — next; highest value; depends on nothing new.
3. **P2** — after P1; reuses eval/conformance machinery.
4. **P5** — independent; can parallel P2.
5. **P3** — last; needs a live model (owner-paused), so deterministic dry-run now, live PASS with the M6 dependency.
6. **P6** — done (this plan + review).

## Non-claims

- This plan is not an implementation of P1/P2/P3/P5; only P4 ships as code this session.
- No live-model result is claimed; P3's live PASS shares the M6 pause.
- Candidate milestone naming (M8) is provisional until the owner accepts it into the roadmap.
