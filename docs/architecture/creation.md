# Creating in the ecosystem

**Status:** map of how each artifact is created today, plus the gate every creation must pass.
**Updated:** 2026-07-22

## Principle

In this project **creation is proposal + gate, never emergence.** Nothing becomes an executable capability the moment it is written. A loop, contract, skill, or agent is generated freely but stays inert until it passes an objective gate and binds an accountable owner. This is the third law — *no capability without verification* — applied to creation itself. It is what lets an unknown team's unknown model generate artifacts without those artifacts escaping the concepts this project enforces.

## What can be created, and how

| Artifact | Authoring procedure (for the agent) | Architecture (how it works) | Gate before it is live |
|---|---|---|---|
| **Loop** | [`bounded-loop-authoring`](../../src/eco_skills/catalog/bounded-loop-authoring/SKILL.md) skill | [no-model-wiki-health](no-model-wiki-health.md), `eco_loops` | M4 promotion: 5 attempts + replay, L0–L2 eligibility |
| **Canonical contract** (`.ai`) | [`ecosystem-contract-change`](../../src/eco_skills/catalog/ecosystem-contract-change/SKILL.md) skill | [runtime-contracts](runtime-contracts.md), M1 compiler | `eco validate` + `eco render --check` + tests |
| **Skill** | [`skill-authoring`](../../src/eco_skills/catalog/skill-authoring/SKILL.md) skill | [skills-harness-sync](skills-harness-sync.md), M6.2 registry | Schema + tests + evidence + owner + adversarial review, then `eco skills sync` |
| **Agent / team** | [`agent-team-authoring`](../../src/eco_skills/catalog/agent-team-authoring/SKILL.md) skill | [general-agent-teams](general-agent-teams.md), [team-authority](team-authority.md) | Manifest schema, narrowing, no delegation escalation, M5 identity, owner |
| **Memory** | (via team workflow) | [private-context-memory](private-context-memory.md), M6.5 | Provenance-bound, TTL-safe, content-free journal |
| **Generation under a new request** | `eco skills propose` → gate → `eco skills promote` | [Gated Self-Creation proposal](../research/2026-07-22-gated-self-creation-contract-proposal-claude.md), `eco_gsc` | Gate (structure, narrowing, secret, hard-stop integrity) + L0 promotion: re-gated, approval bound to the exact digest, no overwrite. Live-proven on a local model. |

## The common shape

Every creation, whatever the artifact, moves through the same states:

```text
proposed  →  validated  →  narrow-checked  →  deterministic gate  →
adversarial gate  →  owner-bound  →  promoted  ⇄  revoked
```

- **proposed** — exists as text; grants nothing; cannot execute.
- **promoted** — passed the gate, recorded with owner and provenance; executable within its bounds.
- **revoked** — withdrawn; remains in history as evidence, no longer executable.

The **adversarial gate** is mandatory (from the Anthropic-migration and Karpathy/ADK principle *validate the judge against broken code*): an artifact must survive an *attack* on it, not just a positive test. A gate that cannot catch a deliberately broken version of the artifact is not a gate, and promotion is refused.

## Autonomy is a scale, not a switch

| Level | Who admits the artifact | When appropriate |
|---|---|---|
| 🟢 **L0 human-approve** | agent proposes → a human confirms → promote | default; D2+ data; anything irreversible |
| 🟡 **L1 auto-gate** | agent proposes → deterministic + adversarial gate auto → promote, human owner accountable after the fact | artifacts with a *deterministic* gate; low risk |
| 🔴 **L2 full-auto, no owner** | — | **forbidden**; breaks accountability and the third law |

Autonomous self-creation is possible (L1) — but only for artifacts whose gate is deterministic, and always with an accountable owner. There is no artifact without a human who answers for it, even one who wrote none of it.

## Invariants (from `.ai/instructions.yaml`)

1. **Proposal ≠ rights** (VERIFIED-STATE).
2. **Narrowing-only** (AUTHORITY-PRECEDENCE): a creation may act within team policy, never widen it.
3. **Adversarial mandatory**: promotion requires the gate to catch a broken version.
4. **Accountable owner always**, even at L1.
5. **Provenance immutable**: who generated it, when, under which request, which digest, which evidence.
6. **Revocable always**.
7. **Model-agnostic gate**: the gate checks the artifact and its output, never trusts the generating model — which is why it holds on any team's LLM.

## Sources

- [`.ai/instructions.yaml`](../../.ai/instructions.yaml)
- [Gated Self-Creation proposal](../research/2026-07-22-gated-self-creation-contract-proposal-claude.md)
- [Skills / harness sync](skills-harness-sync.md), [General agent teams](general-agent-teams.md), [Team authority](team-authority.md)
