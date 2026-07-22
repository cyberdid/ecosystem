---
name: ecosystem-contract-change
description: Change canonical ecosystem contracts and deterministic projections without weakening authority boundaries.
---
<!-- eco-skills:managed surface="portable" registry="1a35599d47efed2e7e09d1f84cd3c5aeaf5710494421f27bcfb03013b1966370" skill="ecosystem-contract-change" -->


# Ecosystem contract change

Use this workflow when a task changes a canonical `.ai` contract, its schema, or a generated client projection.

1. Read `AGENTS.md`, the canonical source, schema, cross-contract validator, relevant ADR, and existing tests.
2. State the authority and compatibility boundaries that must remain unchanged.
3. Change the canonical machine-readable contract before any projection.
4. Render projections through `eco`; do not hand-edit generated managed blocks.
5. Add positive, negative, drift, rollback, and uninstall tests proportional to the change.
6. Run `eco validate`, `eco render --check`, `eco doctor`, focused tests, and the complete regression suite.
7. Record exact evidence and explicit non-claims. A prompt, skill, or compatibility label never grants runtime authority.

Hard stop: refuse a change that silently discards unsupported fields, embeds secrets, overwrites unmanaged files, or bypasses broker and policy enforcement.
