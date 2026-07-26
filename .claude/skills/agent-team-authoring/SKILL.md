---
name: agent-team-authoring
description: Assemble a bounded agent team as an AgentTeamManifest with authenticated identity, budgets, delegation, and no self-expansion of authority.
---
<!-- eco-skills:managed surface="claude" registry="4a823fe6b3a2e49a646ac0ec0cbdb15bc08b1749660972cc91123f300e4c2680" skill="agent-team-authoring" -->


# Agent team authoring

Use this workflow to compose a team of roles for one bounded objective.

1. State the objective, its deadline, and the total budget the whole team may not exceed.
2. Define each role: an id, one bounded job, exact capabilities, a per-role budget, and an expiry no later than the team deadline.
3. Bind each role to an authenticated principal and membership; a role is a verified identity, never a free-text persona or a self-written memory file.
4. Declare delegation edges explicitly; a role may delegate only to a named existing role, never to itself, and never to widen authority.
5. Keep the reviewer separate from the author — no role grades its own output.
6. Verify narrowing: every capability and budget stays within team and project policy, and the sum of role budgets does not exceed the team budget.
7. Pass the gate: manifest schema valid, no delegation escalation, separation of duties intact, accountable owner bound. Keep every role revocable.

Hard stop: a team manifest and a router decision are descriptions, not permission; no role receives authority it cannot prove, and none may expand its own budget, capabilities, or delegation.
