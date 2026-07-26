---
name: ecosystem-contract-change
description: Change canonical ecosystem contracts and deterministic projections without weakening authority boundaries.
---
<!-- eco-skills:managed surface="portable" registry="4a823fe6b3a2e49a646ac0ec0cbdb15bc08b1749660972cc91123f300e4c2680" skill="ecosystem-contract-change" -->


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
