# Model-role separation for source-review (design spec)

**Status:** design; not implemented. Blocks on ADR-006 multi-model evaluation
evidence and an owner decision on the canonical contract change below.
**Updated:** 2026-07-20
**Motivation:** [self-correcting-loop source review](../research/2026-07-20-self-correcting-loop-and-harness-source-review.md) §"stress-test coverage map", gap 4.

## Problem

The fixed `source-review` workflow currently binds exactly one enabled deployment
to all five roles (`src/eco_cli/source_review.py::_verify_deployment` requires
`len(enabled) == 1`; every role call in `_DynamicGovernedExecutor.execute` and
`_build_orchestration_inputs` reads `context.verified.deployment`). When the same
model builds and judges, the Judge inherits the Builder's blind spots — the
"same-model blind spot" failure. The 2026-07-17 live dogfood ran all five roles on
one local model, exactly this antipattern.

## Goal

Let the Judge roles (`verifier`, `reviewer`) resolve to a **different** governed
deployment than the Builder roles (`planner`, `analyst`, `synthesizer`), while
preserving every existing enforcement boundary and staying backward compatible with
the single-deployment profile.

## Non-goals

- No change to the Ed25519 external route-authority path. That path stays
  single-deployment; the split is available only in the base governed composition.
- No new model, adapter or transport. Both deployments remain governed
  local-loopback OpenAI-compatible deployments with their own signed evidence.
- No relaxation of any M1–M5 boundary. Each role call still crosses its own
  `PolicyEngine`, `RunPlan`, evidence verification and durable model bridge.

## Canonical contract change (owner decision required)

Two logical roles instead of one, using the existing open `logicalRoles` map (no
schema change — `deployments.schema.json` already allows arbitrary role keys):

- `review.private` — Judge roles; `candidates: [<judge-deployment-id>]`. Unchanged
  name and meaning; in single-deployment mode it remains the only role and every
  role uses it.
- `review.build` — Builder roles; `candidates: [<builder-deployment-id>]`. Present
  only in split mode.

Role → deployment mapping is fixed by the profile:

```
BUILDER_ROLES = {planner, analyst, synthesizer}   -> review.build candidate
JUDGE_ROLES   = {verifier, reviewer}              -> review.private candidate
```

Mode is inferred: `review.build` absent and one enabled deployment → single mode
(current behavior byte-for-byte); `review.build` present with exactly two enabled
deployments whose ids match the two role candidates → split mode; anything else is
`ECO_SOURCE_REVIEW_DEPLOYMENT_COUNT`.

## Implementation outline (exact touch points)

1. **`_verify_deployment` → parameterize.** Verify one *given* deployment against a
   *given* logical role name (extract the current body; take `deployment` and
   `logical_role_name` as inputs instead of computing "the one enabled").
2. **Add `_resolve_role_deployments(repository, bundle, *, now)`** returning
   `(anchor: VerifiedDeployment, role_deployments: dict[str, VerifiedDeployment])`,
   where `anchor` is the `review.private` (judge) deployment. It verifies each
   distinct deployment once, with its own signed `AdapterConformanceProfile`
   evidence and its own eligible issuer keys.
3. **`CompositionContext`**: add `role_deployments: dict[str, VerifiedDeployment] |
   None = None` and `verified_for(role_id) -> VerifiedDeployment` (falls back to
   `self.verified` when `None`). Extend `route_valid_until` to `min` over the
   deadline and **all** role deployments' `authority_valid_until`.
4. **`_DynamicGovernedExecutor.execute`**: replace each `self._context.verified.*`
   with `verified = self._context.verified_for(invocation.role_id)` then
   `verified.*` — the per-role `PolicyEngine`, `ObservationBindingExpectation`,
   `deploymentPin`, `PinnedOpenAICompatibleDeployment` and `ModelRequest` all bind
   the resolved deployment.
5. **`_build_orchestration_inputs`**: build one `PinnedOpenAICompatibleDeployment`
   per distinct deployment and emit each role's `RouteDecision.spec.deployment`
   from `verified_for(role_id)`.
6. **Route-authority guard**: in `run_source_review`, if split mode (two distinct
   role deployments) **and** `route_records is not None`, fail with a typed
   `ECO_SOURCE_REVIEW_ROUTE_SINGLE_DEPLOYMENT`. The Ed25519 authority signs a
   single-deployment contract; multi-model runs use the base governed path.
7. **`preflight_source_review`**: call `_resolve_role_deployments` so both
   deployments are verified with zero writes; report both deployment ids.

## Verification plan

- **Deterministic (no live model):** extend the CLI test harness
  (`tests/test_m6_source_review_cli.py::_Provider`, a real local HTTP server) to run
  **two** providers. Assert the three Builder role calls hit provider A and the two
  Judge role calls hit provider B; assert single-deployment runs are unchanged;
  assert negatives — missing judge-deployment evidence, a role bound to the wrong
  deployment, and a route-authority run in split mode — all fail closed with their
  typed codes. Convert `test_same_model_blind_spot_requires_model_role_separation`
  from skipped to active.
- **Live (ADR-006 gate):** two distinct local models, one reproducible source review
  where the different-model Judge measurably changes outcomes versus the shared
  model, recorded as evaluation evidence. This is required before any completion
  claim; it is currently blocked because live model iterations are paused.

## Risks

- Touches the freshly-hardened `source_review.py`; land as one reviewable slice and
  rebase on the active M6 branch to avoid collision.
- Fake-provider tests prove **routing**, not that a different model catches real
  blind spots; only the ADR-006 live evaluation proves the actual value.
- Two deployments double the operator evidence ceremony
  (`scripts/provision_local_source_review.py` per deployment).
