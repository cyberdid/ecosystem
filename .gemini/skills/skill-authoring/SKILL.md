---
name: skill-authoring
description: Author a new package-owned skill that earns registry promotion through tests, evidence, and an accountable owner.
---
<!-- eco-skills:managed surface="gemini" registry="72149b048438ccfbd104239d5586ee78a72386f7692ad2e77f1ab6131545bde4" skill="skill-authoring" -->


# Skill authoring

Use this workflow when a request recurs and no existing skill covers it.

1. State the exact repeatable job, its inputs, its bounded output, and the one hard stop that must never be crossed.
2. Write `SKILL.md`: frontmatter `name` and `description`, a numbered procedure, and an explicit `Hard stop:` line.
3. Write the skill's own tests — what it must always do and what it must never do — before proposing promotion.
4. Bind registry metadata: capabilities, dependencies, license, an accountable owner, tests, evidence, and per-harness compatibility.
5. Compute the content digest from the exact `SKILL.md` bytes; keep it deterministic and stable.
6. Pass the gate: schema validity, capabilities within team policy, tests green, and an adversarial review proving the skill cannot be driven to cross its hard stop.
7. Promote only after an owner accepts the skill; `eco skills sync` projects it to every harness. Keep it revocable.

Hard stop: no skill enters the registry without tests, evidence, an owner, and a passing adversarial gate; a proposed skill grants no capability and executes nothing.
