# Read-only flow projections

**Status:** Slice 1 implemented for deterministic replay; live observation and
additional journal adapters remain future work.

**Updated:** 2026-07-26

## Boundary

`FlowProjection` is an observer contract over already recorded evidence. It is
not a planner, policy decision, approval, runtime checkpoint or source of
execution authority.

```text
validated or observed records
→ deterministic projector
→ strict content-free FlowProjection
→ digest validation / JSON replay
→ product graph, inspector and timeline
```

The canonical capability `observability.flow.read` is A0 with no side effect.
It describes access to the projection; it does not grant access to an
underlying journal or widen any run authority.

## Contract

The additive namespace is `flow.ai.ecosystem/v1alpha1`. A projection binds:

- exact project, run and projection identity;
- a source kind, trust tier, explicit boundary and optional head digest;
- ordered content-free nodes;
- explicit edges over known nodes;
- run status and deterministically derived counts;
- a semantic digest over the complete record.

Nodes contain only event type, phase, status, timestamp, safe reason code and
subject binding. Raw prompts, outputs, tool arguments, source excerpts,
credentials and paths are outside this contract.

## Trust is not inferred

| Trust | Required caller statement |
|---|---|
| `authenticated` | An external journal authority already authenticated the source. |
| `validated` | Records validated, but producer authentication was not established. |
| `observed` | A product adapter projected its own stored observation. |

The projector never promotes `validated` or `observed` to `authenticated`.
Runtime projection accepts an explicit `authenticated` caller assertion but
does not itself verify external signatures.

## Determinism and replay

Projection IDs, node IDs, edge IDs, summary and digest are derived from the
same ordered input. No wall-clock creation time is added. Repeating the same
projection yields byte-equivalent JSON after canonical serialization.

`replay_projection` parses and validates an export. Replay:

- performs no model/tool calls;
- grants no capability;
- does not resume or rerun the source workflow;
- rejects projection-digest tampering, unknown fields, dangling edges,
  duplicate IDs, non-contiguous sequences and summary drift;
- for Runtime input, also rejects a broken `previousEventDigest` chain before
  building the observer record.

## Product adapter

Nordrassil feature commit `6424de510191c6dc4f7ab39d1c2d927ec1d1a90e`
and boundary-test follow-up `728dd17d66404538cb5595d7ba084d9487d94e98`
use the contract for real project-bound Deep Research history. Because that
history comes from the product adapter rather than a core journal, it is
labelled:

- kind: `product-observation`;
- trust: `observed`;
- boundary: `product-research-not-governed-broker`.

The private query stays in the product list/detail envelope as a label. The
embedded projection excludes query, trajectory arguments and observations.

## Verification and non-claims

Seven focused core tests prove deterministic replay and fail-closed tamper,
chain, edge, sequence and unknown-field handling. Canonical validation,
projection drift check and doctor pass. The full macOS core regression was attempted; Linux-only
`openat2`/Landlock broker tests fail or skip on this host as before and are not
evidence against the platform-neutral flow package.

This slice does not claim live streaming, journal discovery, authenticated
Orchestration/Loop/Team adapters, graph-authored execution, multi-agent
handoffs without records, or semantic truth.
