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

| Test | gemma4:12b-mlx | gpt-oss:20b |
|---|---|---|
| **P2** structured-output admission | ADMITTED (after normalization) | ADMITTED (clean) |
| **P1** eval, free-text factual suite (judge-validated) | 3/3 PASS | 3/3 PASS |
| **GSC** model proposes a SKILL.md → gate | REJECTED (malformed frontmatter) | **ADMISSIBLE** (ready for human approval) |

Plus an adversarial GSC proposal (self-granted `repository.write`, embedded
secret, "bypass policy") → correctly REJECTED on capability escalation. The gate
had teeth in every case.

**Headline:** a real local model (gpt-oss) self-created a skill that passed the
deterministic gate — the first live proof of gated self-creation on an unknown
local model. A flaky model's malformed output and a self-authorizing proposal
were both rejected.

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

## 4. Real model-behaviour findings (not defects)

- **Structured-output support is flaky and model/prompt-specific.** Under
  Ollama's strict `json_schema` mode, `gemma4:12b-mlx` frequently returns an
  **empty** completion, and `gpt-oss:20b` returns empty on some prompts. The
  models are factually competent (P1: 3/3 free-text each) — they are simply
  unreliable at constrained typed output. Operational consequence: for such a
  model, do not force strict json-mode; take free text and extract (P2 already
  does), or add a retry. This is exactly the split the two gates surface:
  P1 (competence) vs P2 (reliable typed output).
- `gemma4:12b-mlx` also returned empty or malformed frontmatter on the
  SKILL.md generation prompt; `gpt-oss:20b` produced clean, complete artifacts.

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
