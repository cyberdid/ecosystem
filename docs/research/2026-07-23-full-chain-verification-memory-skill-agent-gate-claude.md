# Real concept verification: do memory, skill, and agent-authority compose in one governed task?

**Date:** 2026-07-23
**Author:** Claude (Fable 5), Claude Code
**Status:** working-session record; the capstone dependency verification (all concepts at once)
**Builds on:** [memory](2026-07-23-real-memory-verification-mini-project-claude.md),
[skill-follow](2026-07-23-skill-follow-verification-real-gate-claude.md),
[agent-write](2026-07-23-agent-write-verification-authority-gate-claude.md)

## Question

The earlier notes proved each concept in isolation. The real question for an installed harness is
whether they **compose**: in one governed review, does a stored decision (memory) shape the work,
does a skill drive gate-passing evidence, and is the whole thing bounded by agent authority — and
is **each link still load-bearing** (removing it breaks only its own check)?

## Method — one scenario, all real code

A governed review of a release note, with all three concepts wired together:

- **Memory (real `eco_memory`):** store an arbitrary decision `DEC-9` carrying a non-guessable
  marker `[RETRY-SCOPE-9]` that the model can only emit if it actually read the retrieved record;
  retrieve it via `retrieve_memory` under a read policy.
- **Skill (real `source-review-evidence`):** drives byte-exact evidence.
- **Gate (real `parse_role_output` + `SourceReviewWorkflow._publish_claim_graph`):** admits the
  output and checks every observation is a byte-exact substring of the source in real CAS.
- **Agent (real `eco_teams.contracts.validate_record`):** the review is authored by a `reviewer`
  role delegated from an `orchestrator`; the contract accepts a bounded reviewer and must reject a
  widened one.

Each link has a dependency arm: **−memory** (retrieve nothing → the marker must vanish),
**−skill** (decoy paraphrase skill → the gate must reject), **−authority** (widen the reviewer →
the contract must reject).

## Result — the chain holds and every link is load-bearing (both models)

| Link | Check | gpt-oss:20b | gemma4:12b-mlx |
|---|---|---|---|
| **Agent** | bounded reviewer accepted; widened reviewer rejected (`expands authority`) | ✅ / ✅ | ✅ / ✅ (model-independent contract) |
| **Memory** | marker present **with** memory, absent **without** it | ✅ present / ✅ absent | ✅ present / ✅ absent |
| **Skill** | gate **PASS** with the real skill, **FAIL** with the decoy | ✅ / ✅ | ✅ / ✅ |
| **Full chain** | all three load-bearing together | **PROVEN** | **PROVEN** |

In the positive run a single review carries both memory-derived behavior (each in-scope claim
statement prefixed with `[RETRY-SCOPE-9]`) and skill-derived behavior (evidence that is a
character-for-character quote), and it is authored inside an authority-bounded team the real
contract accepts. Remove the memory and the arbitrary marker disappears; swap the skill for a
decoy and the same real gate rejects the paraphrase; widen the reviewer and the same real contract
rejects it. The concepts compose, and none is decorative.

## Boundary

- Verified on macOS: real memory store/retrieve, the real byte-exact evidence gate over real
  content-addressed storage, and the real team-authority contract, driven by live output from both
  local models. Not run here (the documented WSL boundary): the enforced end-to-end runtime that
  gates the model call through the broker, mints and revokes signed authority, and runs the full
  7-role `SourceReviewWorkflow.run()` state machine.
- The live driver (`full_chain_e2e.py`) is in the session scratchpad, not committed.

## What this closes

The four-part verification roadmap (memory, skill-follow, agent-write, full chain) is complete:
every concept the project defines is exercised as **real code on real cases**, and each is proven
used by the dependency method — the test fails without it. Two contaminated-negative harness flaws
were caught by inspection (not trusted verdicts) and fixed; two honest per-model limitations
(gemma's empty-output and byte-exact-quote drift) were reported rather than smoothed over.
