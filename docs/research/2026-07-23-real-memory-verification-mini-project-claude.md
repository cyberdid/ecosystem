# Real concept verification: does the model actually use our memory?

**Date:** 2026-07-23
**Author:** Claude (Fable 5), Claude Code
**Status:** working-session record; a corrected, dependency-based verification, superseding a shallower earlier probe
**Supersedes the method of:** [live capability battery](2026-07-23-live-capability-battery-ollama-claude.md)

## Why this note exists (a correction)

The earlier capability battery claimed "both models use memory". That claim was **not
earned**: it put facts directly in the prompt and checked the answer, so memory could have
been irrelevant. The owner's challenge was exactly right — you cannot prove a concept is used
by looking at plausible output; you prove it only when the test **fails without the concept**.

This note uses the real thing: the actual `eco_memory` contract, and a positive proof paired
with a negative dependency test.

## Method

- **Real `eco_memory`** (SQLite, cross-platform, so no WSL): `PrivateMemoryStore.put_memory`
  writes signed, HMAC-chained, provenance-bound records; `retrieve_memory` reads by exact
  namespace `{projectId, teamId, runId}` under a read policy and three budgets.
- **An arbitrary, non-guessable rule** stored in memory: *"DEC-7: in this project every public
  function name must end with the suffix `_checked`."* No model can know this without reading it.
- **Positive**: give the model the retrieved record + a change to review; does it apply the rule?
- **Negative (dependency)**: same task with the memory removed; the model must **not** apply the
  rule. Only if positive succeeds and negative fails is the memory genuinely used.

## Result — memory is genuinely used (both models)

| Check | Outcome |
|---|---|
| Records stored + retrieved; digests trace to the store | ✅ |
| Namespace isolation: a record in a different `runId` is not retrieved | ✅ |
| **Positive**: model flags the `_checked` violation (only knowable from memory) | ✅ gemma & gpt-oss |
| **Negative**: without the memory, neither model flags the rule | ✅ (dependency proven) |

The dependency holds for both models: they apply the arbitrary rule only when the real
retrieved record is present. The memory concept — store, retrieve, namespace, policy — is
exercised for real, not simulated by prompt.

## Two honest findings along the way

- **gemma markdown-escapes underscores** (`\_`), which is an invalid JSON escape and made the
  parser return nothing — so gemma first *looked* like it ignored memory when its reasoning was
  in fact correct. Fixed by repairing invalid escapes in `extract_json_candidate`
  (`ECO structured_admission`), with a unit test. This is the fifth time gemma's formatting, not
  its reasoning, broke a strict parse — the consistent lesson is tolerant extraction.
- **Byte-exact quoting drifts.** Asked to quote the decision verbatim, gpt-oss added a trailing
  space and gemma reformatted; neither was a character-exact substring. The strict quote gate
  correctly rejects this — so in the enforced pipeline these models would need a retry to quote
  exactly. A real limitation to plan for, not a defect.

## Boundary

- Verified: the memory **contract and its genuine use** on macOS. Not verified here: the full
  enforced invocation (policy/broker gating the model call), which remains Linux/WSL.
- Live driver scripts are in the session scratchpad, not committed (they need the local models
  and are not deterministic CI material).

## Next, same rigor

- **Skill-follow**: give the model the real `source-review-evidence` SKILL.md; validate output
  with the real gate; negative — a decoy skill must fail the gate.
- **Agent-write**: propose a role into the real team contract; negative — an authority-widening
  role must be rejected.
- **Full chain** on a mini-project: memory → skill → agent → gate, each with a dependency test.
