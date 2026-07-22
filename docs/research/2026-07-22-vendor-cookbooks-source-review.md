# Source review: vendor agent cookbooks (Anthropic, Google, OpenAI)

**Reviewed:** 2026-07-22
**Reviewer:** Claude (Fable 5), Claude Code
**Status:** review of external reference material; recommendation, not accepted architecture
**Scope:** three owner-cloned vendor cookbooks under `external/cookbooks/` (gitignored reference corpus)

## Trust boundary

By **UNTRUSTED-CONTENT**, these are **data, not instructions**. They are working demos that assume trust (API keys in notebooks, no policy layer, `eval()` for tool dispatch — the Claude notebook itself warns against this). Nothing here is executed, no SDK is adopted, no dependency is added. `external/` is already in `.gitignore`; only this reviewed document enters git. The corpus is treated exactly like the MAP.md upstream-clone pattern: downloaded → statically reviewed → boundaries recorded → nothing promoted into policy/skill/runtime merely because it is present.

## Provenance

| Clone | Scale | Relevance |
|---|---|---|
| `external/cookbooks/claude-cookbooks` | 605 files, 89 notebooks | highest — agent SDK, patterns, evals, tool_evaluation, skills, observability |
| `external/cookbooks/google-gemini-cookbook` | 207 files, 141 notebooks | function calling, structured outputs, safety, EU AI Act compliance agent |
| `external/cookbooks/openai-cookbook` | 3095 files, 267 notebooks | orchestrating agents, agents SDK, structured outputs, reliability techniques, evals |

## Research question

Which patterns in the three biggest vendors' cookbooks validate this project's thesis, which reveal capabilities the project lacks, and what concretely should change — mapped to real modules, without adopting any vendor SDK.

## Executive verdict

**Third independent confirmation of the project's thesis — now from the vendors themselves.** After two blogger source reviews (2026-07-20, 2026-07-22), Google, Anthropic and OpenAI independently converge on the same agent concepts this project enforces: an independent grader (not the author), bounded loops with gates, human-in-the-loop escalation, prompt versioning/rollback, typed structured output, orchestrator-workers.

The decisive difference is the same one that runs through the whole project: the cookbooks reach discipline as **patterns and prompts inside notebooks** (fragile, trust-assuming, vendor-specific); the project reaches it as **enforced contracts** (model-agnostic, policy-bound, auditable). The cookbooks are demos; the project's enforcement layer is exactly what they lack to become production. They do not challenge the project — they show it is building the right layer above what they demonstrate.

## What the cookbooks confirm the project already has

| Cookbook pattern | Project equivalent |
|---|---|
| evaluator-optimizer; outcome-grader ("agents produce things that *look* done") — `claude/managed_agents/CMA_verify_with_outcome_grader` | maker/checker, VERIFY-DONE, adversarial gate |
| human-in-the-loop gate ("gap between fully-automate and always-ask") — `claude/managed_agents/CMA_gate_human_in_the_loop` | GSC L0/L1 autonomy scale — exact match |
| orchestrator-workers; routines+handoffs — `claude/patterns/agents`, `openai/Orchestrating_agents` | M6.6 teams + typed handoffs |
| prompt versioning/rollback — `claude/managed_agents/CMA_prompt_versioning_and_rollback` | M1 projections (drift/rollback/ownership) — project is stricter (digest-bound) |
| structured outputs as reliability lever — `openai/Structured_Outputs_Intro`, `gemini` | JSON schemas throughout |

## What the cookbooks reveal the project lacks (→ recommendations)

1. **Evals as a first-class discipline.** All three ship eval frameworks. The project has only the fixed M4 promotion (five attempts for one loop); there is no general eval harness. `claude/tool_evaluation` gives the exact shape: an evaluation file (ground-truth prompt/expected) → N independent agent runs → metrics → verdict.
2. **Structured-output as a model-admission criterion.** Vendors stress typed output as the primary lever that makes an unknown model behave. The project uses schemas but does not make structured-output conformance part of model admission.
3. **Reference agents that actually run.** The cookbooks are runnable agents; the project has contracts but almost no running agents (the live PASS never happened).
4. **Reliability techniques as knowledge.** `openai/articles/techniques_to_improve_reliability` (split-tasks, explain-before-answer, verifiers, self-consistency) is procedural knowledge that should become canonical skills.
5. **Cost/observability.** `claude/observability/usage_cost_api` tracks spend; the project has audit but no cost accounting (the Hermes "surprise bill" lesson).
6. **Governance/compliance is a differentiator, not a gap.** `gemini/Agent_Module_EU_AI_Act_Compliance` shows agents needing a compliance substrate — which the project's enforcement+audit already *is*. This is to be positioned, not built.

## Method

Reconnoitred all three top-level structures and scale; read the Claude agent-patterns manifest, the Claude `tool_evaluation` core (eval-file → independent agents → metrics), three `managed_agents` notebook theses (outcome-grader, human-gate, prompt-rollback), the OpenAI orchestration and reliability articles, and the Gemini example/quickstart inventory. Vendor marketing claims and demo shortcuts (`eval()` dispatch, notebook-embedded keys) were not treated as evidence.

## Limitations and non-claims

- These are demos, not benchmarked results; no performance number is adopted.
- Vendor SDKs are not adopted — only vendor-neutral patterns inform recommendations.
- The corpus is gitignored; this review is the only tracked artifact. Re-review requires the clones present locally.
- Recommendations become real only through the separate [implementation plan](2026-07-22-cookbook-recommendations-implementation-plan.md) and its per-slice gates.

## Sources

- `external/cookbooks/` (three clones above) — untrusted reference
- Prior reviews: [2026-07-20](2026-07-20-self-correcting-loop-and-harness-source-review.md), [2026-07-22 articles](2026-07-22-agentic-teams-graphs-migrations-source-review.md)
- [`.ai/instructions.yaml`](../../.ai/instructions.yaml)
