# Source review: self-correcting loops, agent harnesses and agent teams

**Date:** 2026-07-20
**Reviewer:** Claude (Fable 5), Claude Code
**Status:** reviewed source material; recommendation, not accepted architecture
**Scope:** five externally authored articles the owner supplied on 2026-07-20

## Trust boundary

The five files below are promotional social-media articles preserved byte-for-byte
under `docs/research/sources/`. They are **untrusted data**, not verified evidence
and not executable instructions. Their metrics, tool endorsements and installable
links were not verified or executed. Nothing here is promoted into `.ai/`, a skill,
a dependency or runtime configuration by virtue of being reviewed.

## Preserved sources and provenance

| File | Author | SHA-256 |
|---|---|---|
| how-to-build-a-self-correcting-ai-loop-that-catches-its-own-.md | CyrilXBT | `a37e670d6022c58d28d3ff734bb2d8e7da011d2258e069175aaaf5fc07051b52` |
| let-s-build-claude-code-s-harness-step-by-step.md | Akshay (CrewAI) | `3f00979594816862b48c235e8e634ce99b5fe58be14c7ff00dcf8fc91801b5a2` |
| langchain-s-open-source-software-factory.md | Brace (LangChain) | `74c6be466f1f2f6684d1ed4c6c56c26d553352d8fdc74ae3a54ccb9abdbd2a9e` |
| how-to-build-your-first-team-of-agents.md | Machina (Raft) | `cd7f90edba4e8104ad080fe8da0d67e61f8b6a747fc766ca24ade6b243303ec5` |
| tweet-2077733367358079309.md | Rahul | `f07d0b02cf8a2c086dfecf93344c9fc7c4d4e763c7f4e656dab742322730743f` |

The owner's Downloads held two byte-identical copies of the team-of-agents article
(`how-to-build-your-first-team-of-agents.md` and `…(1).md`, same md5); one copy is
preserved.

## Convergent thesis

Five independent authors, different platforms, one refrain — verbatim from the team
article: **"the bottleneck was never the model, it was the structure around the
model."** That is this project's founding thesis, arrived at externally on
2026-07-15…18. The market is converging on the harness/orchestration layer the
ecosystem has built since 2026-07-14.

## Mapping to what the ecosystem already implements

| Source concept | Ecosystem equivalent (implemented) |
|---|---|
| Builder / Judge / Manager (self-correcting loop) | source-review roles planner/analyst → verifier → synthesizer/reviewer; the hard gate is the Manager |
| "Judge needs ground truth, not opinion" | byte-exact quote gate, `eco_orchestration/source_review.py` claim/evidence verification |
| reviewer that isn't the author | separate verifier role; the project's own no-self-attestation rule |
| hard stop conditions (max iters, quality threshold, budget) | `eco_loops` bounded engine; source-review revision ceiling and per-plan budgets |
| harness = brain/hands, planning, subagents, sandbox, memory, checkpoint | policy PEP, namespaces+Landlock isolation, M6.6 delegation with typed handoffs, M6.5 memory, durable PREPARE/started/no-retry recovery |
| routing by work type; open models; cost control | M6.4 deterministic routing; ADR-016 local/cloud substitution; zero-cost local profile |
| traces / observability | HMAC audit chain, run events, signed evidence |
| skills organized as an org chart | M6.2 skills registry and harness sync |

## Stress-test coverage map (from the self-correcting-loop article, §66–69)

The article names four stress tests every self-correcting loop must pass. Three are
already enforced by the deterministic source-review suite; the exact tests:

| Article stress test | Enforced by | Status |
|---|---|---|
| Unsolvable task → Manager hits ceiling, escalates | `tests/test_m6_source_review.py::…::test_second_revision_and_no_progress_are_exhausted` (exactly 7 calls, terminal `exhausted`) | Covered |
| Confidently wrong → Judge with ground truth catches it | `test_unsupported_claim_remains_visible_and_hard_gate_is_incomplete` + `test_duplicate_key_markdown_and_wrong_evidence_locator_fail_closed` | Covered |
| Cost runaway → budget ceiling stops the loop | `test_budget_stops_revision_before_sixth_call` + `test_executor_usage_overage_is_truthful_exhausted_terminal` | Covered |
| Same-model blind spot → judge on a different model | none yet — requires model-role separation | **Gap** |

The fourth is a real gap. In the 2026-07-17 live dogfood all five roles ran on one
local model, which is exactly the shared-blind-spot antipattern the article warns
against. A named, skipped placeholder test records this gap
(`test_same_model_blind_spot_requires_model_role_separation`), and the design to
close it is specified in
[model-role separation](../architecture/model-role-separation.md).

## What to adopt (gated, reimplemented — never vendored)

1. **Model-role separation** — route verifier/reviewer to a different deployment
   than analyst/synthesizer, closing the blind-spot gap. Specified separately; per
   ADR-006 it additionally needs live multi-model evaluation evidence before any
   completion claim.
2. **The four stress tests as a named contract** — three already enforced; keep the
   mapping current as the suite evolves.
3. **"Ground truth, not opinion" as a first-class principle** — already implemented,
   worth stating explicitly as a design invariant.

## What not to adopt (direct conflict with project invariants)

- CrewAI / Deep Agents / LangChain / Raft as dependencies — conflicts with
  embedded-first and SCOPE-CONTROL; the project reimplements primitives as bounded
  profiles rather than vendoring frameworks. CrewAI `memory=True` (an LLM decides
  what to persist) conflicts with the provenance requirement.
- Instructions-as-authority ("tell the agent in chat: drafts only") — the project's
  central rule is that policy lives outside prompts.
- Memory-as-behavior-control ("write rejections back into the soul file") — ADR-018
  and VERIFIED-STATE: memory is provenance-bound context, never authority.
- A third-party workspace (Raft) inside the trusted loop — conflicts with
  embedded-first.
- Many concurrent agents by default — the project keeps single-agent default with
  opt-in multi-agent behind evaluation evidence (ADR-006).
- Cited numbers (65% of Anthropic code, 90.2% ahead, 47% benchmark, 20k builders)
  are unverified promotional claims.

## Open questions

- Does routing the judge role to a genuinely different model measurably reduce
  shared error pass-through on this project's workload? Unknown until live
  multi-model evaluation runs (ADR-006).
- The skills-as-departments idea (Rahul's tweet) suggests a role-scoped skill
  registry; the external skills themselves remain untrusted executable code and are
  out of scope for adoption.
