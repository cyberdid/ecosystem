# M6 live-dogfood session: findings and Codex handoff

**Date:** 2026-07-20
**Author:** Claude (Fable 5), Claude Code — implementing/review agent for this session
**Branch:** `codex/m6-functional-orchestration`
**Status:** working-session record and handoff; not a completion claim
**Audience:** the Codex implementation agent and the project owner

## 1. Scope of this session

The owner asked to complete M6. This session (2026-07-17 → 2026-07-20):

1. committed the previously uncommitted M6 working tree as reviewable slices;
2. completed the remaining M6.4 item — durable route consumption and CLI
   composition;
3. applied the M6.2 skills sync to the repository surfaces (dogfood);
4. scripted the operator evidence ceremony and provisioned one real local
   deployment;
5. drove the first live `eco team run source-review` attempts against a real
   llama.cpp loopback endpoint, found three genuine defects, fixed them with
   regression tests;
6. recorded everything here and in the wiki. Live model iterations are now
   **paused by owner instruction**; every next step below is deterministic.

## 2. Commits added on this branch (oldest first)

| Commit | Content |
|---|---|
| `95b2964`..`44d4e20` | Eight slices committing the entire M6.1–M6.7 working tree plus the M6.0 docs (previously uncommitted, ~19k lines) |
| `4b90f65` | Fix for the random hosted-Windows failure: the Ed25519 tamper subtest replaced the first signature character with a literal `"A"`, a no-op whenever the fresh signature already started with `"A"` (~1/64 of runs) |
| `c3eda74` | First dogfood application of `eco skills sync`: 14 projections into `.agents`, `.claude`, `.gemini`, `.ai/skills/projected`, plus copilot/cursor aggregates and the lockfile |
| `42949e7` | M6.4 completion: `DurableRouteConsumptionJournal` (private HMAC chain, single-use, idempotent same-consumer replay, fallback-predecessor rule, immutable rows), pure `verify_route_binding`, `eco route plan`, and `--route-decision/--route-request` consumption in `eco team run source-review` |

Uncommitted at the time of writing (this session's live-dogfood fixes; committed
together with this document):

- `src/eco_runtime/adapters.py` — two fixes (§3.1, §3.2);
- `src/eco_cli/source_review.py` — transport ceiling (§3.3);
- `scripts/provision_local_source_review.py` — operator ceremony (§4);
- `.ai/deployments.yaml`, `.ai/trust.yaml`, `.ai/evals/observed/` — one real
  enabled local deployment with signed observation evidence;
- `loops/source-review-dogfood/` — the dogfood source bundle;
- tests for all of the above.

## 3. Defects found by live dogfooding (all fixed, all with tests)

### 3.1 Provider grammar silently degrades on unexpressible schema keywords

llama.cpp b9652 fails grammar compilation when a JSON Schema contains
`minLength`/`maxLength` (`error parsing grammar: number of repetitions exceeds
sane defaults`) and then **falls back to unconstrained generation** instead of
rejecting the request. Small models then emit wrapper objects or thinking prose
that fails eco-side validation. OpenAI structured outputs likewise excludes
these keywords, plus `uniqueItems`.

Fix: `grammar_safe_response_schema()` in `src/eco_runtime/adapters.py` — the
wire `response_format` schema is a documented projection that drops `$schema`,
`minLength`, `maxLength`, `uniqueItems`. This is not a silent downgrade: the
authoritative validation of the response against the **complete** profile
schema is unchanged (`eco_orchestration/source_review.py:223`). Verified live:
with the projection the constrained output has exactly the schema's keys.

### 3.2 Endpoint-binding record id collided across runs

`PinnedOpenAICompatibleDeployment` derived the `EndpointBinding` record id from
deployment id + endpoint only, while the sealed record digest includes
`resolvedAt`/`validUntil`. Any second run with a new run id against the same
durable store hit `ECO_STORE_ID_CONFLICT` at PREPARE. The restart test missed
it because same-run-id replay short-circuits before insertion.

Fix: the id is now content-addressed over deployment id, endpoint, resolvedAt
and validUntil, so later resolutions coexist as immutable history. Regression:
`test_second_run_with_new_run_id_shares_the_durable_store` (two runs, two run
ids, one store, ten provider calls).

### 3.3 Per-call transport ceiling too tight for CPU backends

The composed `timeoutMs` was capped at a literal 120 s and the pinned
deployment's default `maximum_timeout_ms` matched it. A legitimate slow local
CPU backend (~100 tok/s prompt, ~5 tok/s generation) cannot finish an
analyst-size call in 120 s. The source-review profile now passes
`_MODEL_TRANSPORT_TIMEOUT_MS = 300_000` at both construction sites; every call
remains fenced by the run deadline, durable budgets and started/no-retry
accounting. The adapter default stays 120 s.

## 4. Operator ceremony is now scripted

`scripts/provision_local_source_review.py` performs the previously manual,
blocking key/evidence ceremony in one command: probes the declared loopback
endpoint (plain text + strict JSON-schema structured output), writes the
`AdapterConformanceProfile` into `.ai/evals/observed/`, and signs the envelope
into a private external path with the operator key from the environment. The
runtime still never signs its own evidence. Suite digest
`aa8ed45e…441f5a` is pinned in `.ai/trust.yaml`.

Provisioned deployment: `local-llamacpp-gemma` (llama.cpp `b9652`, loopback
`env:ECO_LOCAL_OPENAI_ENDPOINT`, currently
`gemma-4-26B-A4B-it-UD-Q4_K_XL.gguf`, hf-snapshot `3bb10d59…`). Keys and
envelopes live under a private external directory and are not in Git.

## 5. Live-run status (honest)

Sixteen live attempts were made. The enforcement chain is **proven live
end-to-end**: canonical validation → signed-evidence verification → route plan
→ durable single-use route consumption (a second consumer was correctly denied
with `ECO_ROUTE_ALREADY_CONSUMED`) → policy decisions → durable model PREPARE →
real loopback HTTP calls → CAS artifacts → truthful terminal results. One
2026-07-17 planner operation reached `succeeded` in the durable store.

A full five-role PASS has **not** happened yet. The residual failures are model
capability, not harness defects, and the deterministic gates caught every one:

- duplicate claim/evidence ids (uniqueness gate);
- paraphrased citations (byte-exact quote gate,
  `eco_orchestration/source_review.py:811`);
- invented claim ids in verification (exact-coverage gate);
- `verified` status without supporting evidence (support gate).

Progression by model: gemma-4-E2B reached the analyst stage; gemma-4-26B-A4B
(CPU) passed the citation gate and reached the verifier. GPU was unavailable
during this session (a Windows game held it at 100%; CPU prompt ≈ 100 tok/s).
Question-text shaping in `loops/source-review-dogfood/question.txt` improved
compliance per stage but oscillates on a small model at temperature 0.

## 6. Next steps for Codex — no LLM required

Priority order; every item is deterministic and CI-verifiable.

1. **Merge hygiene.** Open the PR for `codex/m6-functional-orchestration` to
   `main`; confirm hosted Linux/macOS/Windows CI is green (the Windows flake is
   fixed by `4b90f65`).
2. **Role-instruction hardening (contract change, no model needed).** The four
   discipline rules that live in the dogfood question (§5) belong in the
   packaged role instructions under
   `src/eco_orchestration/profiles/source-review.v1/`: unique claim/evidence
   ids, byte-exact verbatim quotes, exact claim coverage, verified-requires-
   supporting-evidence. Update the profile digests and their tests. This makes
   the workflow model-agnostic instead of question-dependent.
3. **M6.8 deterministic gates.** Full regression (currently 699 tests),
   Python 3.11 + 3.12 runs, offline wheel build/verify/install smoke including
   the seven new packages and the skills catalog, leak-sentinel scans over new
   journals (route consumption, memory, teams), repository byte/mtime identity
   checks after CLI operations.
4. **Release scaffolding for `0.8.0`.** README/architecture/roadmap status
   refresh, a completion report that separates deterministic evidence from the
   pending live observations, version bump — gated on an independent review per
   the project's no-self-attestation rule.
5. **Deferred, explicitly out of current scope (owner: "поки без llm тестів").**
   The live five-role PASS. Cheapest path when resumed: free GPU (a single run
   drops from ~15 min to ~2 min) or a stronger local/loopback backend; then one
   `provision_local_source_review.py` + `eco route plan` + `eco team run
   source-review` cycle. Item 2 above should land first — it directly targets
   the observed failure modes.

## 7. What this session does not claim

No five-role live PASS, no L-level promotion, no provider-quality claim, no
prompt-injection immunity, no cross-platform live proof, no 0.8.0 release. The
single-use route denial and the durable-store conflict were observed once each
on one host; their regression tests, not the anecdotes, are the evidence.
