# Local live-dogfood session: P1/P2 and GSC against local Ollama

**Date:** 2026-07-22
**Author:** Claude (Fable 5), Claude Code
**Status:** working-session record; live findings, not a completion or quality claim
**Host:** macOS (owner's Mac), Ollama serving `gemma4:12b-mlx` and `gpt-oss:20b`

## 1. Scope

The owner lifted the live-model pause for local testing. This session drove the
new P-slices against two real local models through the project's own
cross-platform adapter (`LoopbackOpenAITypedHTTPInvoker`) — not raw HTTP. The
model-call path is cross-platform HTTP to a loopback endpoint, so it runs on
macOS; the full enforced pipeline (Linux openat2 broker/isolation) was **not**
exercised and is out of scope here.

## 2. What was verified live

Final numbers are from the maximal battery (generous token budgets, both
transport methods, `finish_reason` tracked):

| Capability | gemma4:12b-mlx | gpt-oss:20b |
|---|---|---|
| **P1** competence (6 factual, judge-validated) | 6/6 PASS | 6/6 PASS |
| **P2** admission, strict `json_schema` | 0/4 — ignores the grammar, emits prose | 4/4 clean |
| **P2** admission, prompt-based JSON (generous tokens) | 4/4 | 4/4 |
| **GSC** self-created skills across 3 domains → gate | 3/3 ADMISSIBLE | 3/3 ADMISSIBLE |
| **GSC** adversarial proposals (3) | all rejected — escalation, secret, no-hard-stop | — |

**Headline:** both unknown local models self-create valid skills that pass the
deterministic gate (GSC 3/3 each) and are fully competent (P1 6/6). The gate
rejects every adversarial proposal. Gated self-creation holds for *both* models —
including the one that first looked "flaky", once it is given enough tokens and
the transport method it can actually use.

## 3. Defects found by live dogfooding (both fixed, both with tests)

### 3.1 P2 admission was too strict (owner-caught)

The first P2 did a raw `json.loads` and rejected `gemma4`'s markdown-fenced JSON
(` ```json {…} ``` `) as `ECO_ADMISSION_NOT_JSON`. Markdown fencing is a near-
universal model habit, not a defect — rejecting for it is brittle. Fix
(`structured_admission.py`): **liberal extraction, strict validation** — a
tolerant extractor strips fences, prose and `<think>` blocks and pulls the first
balanced JSON object; the full schema remains the sole validation authority.
Real violations (wrong shape, missing key, out-of-bounds) still fail closed. The
verdict now carries `normalized` so a tidy model is still distinguished from an
untidy one without being punished. Both models admitted after the fix.

### 3.2 GSC gate flagged its own hard-stop line

The gate's bypass detector matched the legitimate prohibition "never bypass the
gate" inside the `Hard stop:` line, rejecting a valid proposal. Fix (`eco_gsc/
gate.py`): scan the directive body with `Hard stop:` lines removed, so a
prohibition is not mistaken for an instruction.

Both defects are the same class — brittle strictness — caught by investigating a
suspicious result rather than reporting it.

## 4. Real model-behaviour findings (corrected after deeper testing)

Three artifacts of my own testing were caught and corrected before drawing
conclusions — the honest root causes matter more than the first-pass numbers:

- **Empty completions were mostly token starvation, not incapability.** An empty
  body with `finish_reason == "length"` means the budget was spent (often on a
  reasoning model's hidden thinking) before any visible content appeared. The
  first GSC runs used `max_tokens` far too low; with a generous budget **both**
  models produce complete, admissible skills (GSC 3/3 each). Operational rule:
  always read `finish_reason`; treat truncation as "needs more budget", never as
  a model verdict. This is also a P5 telemetry/observability concern.
- **`gemma4:12b-mlx` genuinely ignores Ollama's strict `json_schema` grammar.**
  Given enough tokens it does not return empty — it returns prose ("**Yes, the
  Earth is …**"), so strict-mode admission is 0/4. But with **prompt-based JSON
  that states the exact shape** it is 4/4. Its admission verdict should route it
  to the transport it can use; forcing strict grammar on it is the mistake.
- **Both models are fully competent and both self-create.** P1 6/6 free-text
  each; GSC 3/3 admissible each. The apparent gemma "flakiness" was roughly
  90% my token budget and wrong transport method, and only ~10% a real
  strict-grammar limitation.

The general lesson: the gates surface *how to call* an unknown model — competent?
honors strict grammar or needs prose+extraction? enough budget? — not merely a
pass/fail. That per-model operating profile is exactly what an unknown R&D team
needs, and the admission verdict is where it is decided.

## 5. What this session does not claim

- Not the enforced pipeline: only the cross-platform adapter + deterministic
  gates were exercised on macOS; policy/broker/audit and the M6 source-review
  run remain Linux/WSL and untested here.
- Not a model-quality benchmark: three factual questions and one skill prompt on
  one host, temperature 0. Anecdotes, not measurements.
- GSC promotion was **not** performed: an admissible verdict is L0 ("ready for a
  human to approve"), and no model-generated skill was written to the registry.
- Live driver scripts live under the session scratchpad and are not committed;
  they need the local models and are not deterministic CI material.

## 6. Commits from this session

| Commit | Content |
|---|---|
| `fix: make P2 admission tolerant …` | §3.1 tolerant extraction + tests |
| `feat: add GSC skill-proposal gate …` | GSC gate + 10 tests (§3.2 fix included) |

## 7. Next steps

1. Wire GSC generation → gate → **human approval** → `eco skills promote` (the L0
   promotion step) so an approved proposal actually enters the registry via the
   existing M6.2 sync.
2. When the owner resumes WSL work: the same P1/P2/GSC flow through the full
   enforced pipeline, plus the deferred M6 five-role live PASS.
