# Real concept verification: does the model actually follow our skill?

**Date:** 2026-07-23
**Author:** Claude (Fable 5), Claude Code
**Status:** working-session record; dependency-based verification of skill-following
**Method inherited from:** [real memory verification](2026-07-23-real-memory-verification-mini-project-claude.md)

## Question

Does giving a model the real `source-review-evidence` skill make it produce output that passes
the **real** source-review gate — and does it **fail without that skill**? Following the owner's
standard: a concept is only proven used when the test **fails without it**.

## Method — real code, no proxies

- **Skill under test:** the real `src/eco_skills/catalog/source-review-evidence/SKILL.md`, read
  from disk (its discipline: "every observation must be one short contiguous
  character-for-character quote … never paraphrase").
- **Admission:** the real `parse_role_output` (`eco_orchestration.source_review`) with the real
  analyst output schema (`load_packaged_role_profile("analyst")`). Strict JSON + schema, no fence
  repair — exactly what the enforced pipeline applies to a role's output.
- **Gate:** the real `SourceReviewWorkflow._publish_claim_graph`, run on a real
  `ContentAddressedArtifactStore` built by the project's own test fixture. Its decisive predicate
  (`source_review.py`): `evidence["observation"].encode("utf-8") in <source bytes read from CAS>`
  — a byte-exact substring check against content-addressed storage, plus unique ids and a valid
  source-entry binding.
- **The only variable is the skill.** The output-shape contract handed to the model is
  discipline-neutral (it mirrors the real schema, where `observation` is just a string); whether
  the observation must be an exact quote or a paraphrase is decided **only** by the skill text.
  - **Positive:** the real skill.
  - **Negative (dependency):** a decoy skill with the same JSON structure but the opposite rule
    ("paraphrase in your own words; never a verbatim substring").

## Result — the skill is genuinely followed (both models)

| Model | Positive (real skill) | Negative (decoy skill) | Dependency |
|---|---|---|---|
| gpt-oss:20b | **gate PASS** — 4 claims, all 4 observations byte-exact | **gate FAIL `role-failed`** — 4 paraphrases, none a substring | **PROVEN (clean)** |
| gemma4:12b-mlx | **gate PASS** — byte-exact quote | **gate FAIL** — no admissible output (empty at `finish=length`) | **PROVEN** |

The cleanest demonstration is **gpt-oss**: same model, same source, only the skill changed. With
the real skill it emits verbatim quotes (e.g. `The gateway now aborts a request after exactly 3
failed attempts`) that the byte-exact gate admits; with the decoy it emits paraphrases (`Requests
stop after exactly three unsuccessful attempts.`, a ` ` narrow space, "three" for "3") and
the **same real gate rejects every one** at `_publish_claim_graph`. The skill's exact-quote
discipline — not the model's default — is what earns the gate.

## Two honest findings

- **The negative arm was contaminated on the first run.** The output-shape contract I appended to
  both arms said `"observation": "<exact quote>"`, so even the decoy told the model to quote.
  gpt-oss followed it and the decoy wrongly "passed". This was a harness flaw, not a model
  result; fixed by making the contract discipline-neutral (matching the real schema, which never
  says "exact quote"). Caught by inspecting the output, not by trusting the verdict.
- **gemma's negative fails by non-admission, not by the byte-exact predicate.** Under the decoy
  "summarize" instruction gemma returns empty content at `finish=length` (its reasoning consumes
  the budget), even at 4400 tokens. The dependency still holds — with the real skill it produces a
  byte-exact quote that passes; without it, nothing admissible survives — but the *mechanism* is
  only shown cleanly on gpt-oss. Reported rather than tuned away.

## Boundary

- Verified on macOS: the real admission + the real byte-exact evidence gate over real
  content-addressed storage, driven by live model output. Not run here: the full 7-role
  `SourceReviewWorkflow.run()` state machine (needs fabricated downstream role outputs and budget
  sizing) and the Linux-only source ingestion (`_LinuxAnchoredSourceReader`). The end-to-end
  state-machine run belongs to the **full-chain** step next.
- The live driver (`skill_follow_e2e.py`) is in the session scratchpad, not committed (it needs
  the local models and is not deterministic CI material).

## Next, same rigor

- **Agent-write:** propose a role into the real team contract; negative — an authority-widening
  role must be rejected.
- **Full chain** on a mini-project: memory → skill → agent → gate, each with a dependency test.
