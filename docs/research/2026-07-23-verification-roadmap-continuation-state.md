# Continuation state — concept verification roadmap

**Date:** 2026-07-23
**Purpose:** durable handoff so work continues precisely after a context compaction.
**Read this first when resuming.**

## Where things are

- Repo is **`cyberdid/ecosystem`** (transferred from Pylypko1021 to the paid account; old URL
  redirects). Working on branch **`main`**. Everything is committed and pushed; hosted CI is
  **green on all 8 jobs** (Linux/macOS/Windows × py3.11/py3.12).
- PR #3 (M6 + P1–P5 + GSC) is **merged into main**. gh CLI is logged in as `Pylypko1021`
  (collaborator with push access) — push works.
- Environment: **macOS + local Ollama** serving `gemma4:12b-mlx` and `gpt-oss:20b`. **WSL is not
  available**, so the enforced runtime (openat2 broker, isolation, live 5-role source-review
  PASS, key ceremony) is out of scope; the concept layer (memory, skills, gates, model calls) is
  cross-platform and testable now.

## The task: verify every concept is genuinely used

Method (the owner's standard): **positive proof + negative dependency test** — a concept is only
proven used when the test **fails without it**. Not "plausible output".

| Concept | Status |
|---|---|
| Memory (`eco_memory`) | ✅ verified — dependency-proven (`2026-07-23-real-memory-verification-mini-project-claude.md`) |
| Skill-creation (GSC gate + L0 promote) | ✅ proven live earlier |
| Skill-follow (real `source-review-evidence` SKILL.md → real gate; decoy negative) | ✅ verified — both models (`2026-07-23-skill-follow-verification-real-gate-claude.md`) |
| Agent-write (real team contract; authority-widening role rejected) | ✅ verified — both models (`2026-07-23-agent-write-verification-authority-gate-claude.md`) |
| Full chain: memory → skill → agent → gate | ✅ verified — both models (`2026-07-23-full-chain-verification-memory-skill-agent-gate-claude.md`) |

**The four-part verification roadmap is COMPLETE** (2026-07-23): every concept the project defines
is exercised as real code on real cases and proven used by the dependency method (the test fails
without it). If resuming after this point, the concept-verification work is done — see the four
notes above and `wiki/log.md`.

## Operational lessons (already in code, restate so they aren't re-learned)

- Encoded in `eco_runtime.model_reliability` (finish_reason/transport) and
  `eco_runtime.structured_admission` (tolerant extraction + invalid-escape repair).
- **Generous token budgets**; always check `finish_reason` — empty + `length` = truncation, not
  failure, retry with more tokens.
- **gemma** ignores strict `json_schema` grammar (emits prose) → use **prompt-based JSON with the
  explicit shape**; it also markdown-escapes underscores (`\_`) — the extractor now repairs that.
- **Byte-exact quotes drift** (trailing space / reformatting); the strict quote gate correctly
  rejects — plan a retry for exact-quote workflows.
- Live driver scripts live under the session scratchpad (not committed; they need the models).

## Recording discipline

Every significant finding = a `docs/research/` note + a `wiki/log.md` entry + a
`docs/research/README.md` row + its own commit. Keep this up.

## Immediate next action on resume

The concept-verification roadmap is complete (all four notes above are committed). No verification
step is pending. If the owner wants more, the open extensions are all **WSL/Linux-gated**: the
enforced end-to-end runtime (broker-gated model call, signed-authority mint/revoke, the full
7-role `SourceReviewWorkflow.run()` live PASS). Otherwise, await the owner's next direction.
