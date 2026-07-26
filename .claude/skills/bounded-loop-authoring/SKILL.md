---
name: bounded-loop-authoring
description: Author a bounded feedback loop with an independent gate, evidence boundary, explicit budgets, and hard stops.
---
<!-- eco-skills:managed surface="claude" registry="4a823fe6b3a2e49a646ac0ec0cbdb15bc08b1749660972cc91123f300e4c2680" skill="bounded-loop-authoring" -->


# Bounded loop authoring

Use this workflow only for a repeated process whose state transition and stop conditions can be made explicit.

1. Define one immutable input, one state schema, one artifact boundary, and one independently evaluated gate.
2. Declare maximum cycles, attempts, elapsed time, tokens, cost, artifact bytes, and side effects before execution.
3. Make each transition deterministic from the current validated state and evidence references.
4. Require a durable checkpoint before the next cycle and idempotency for every retryable effect.
5. Stop on success, exhausted budget, deadline, repeated state, invalid output, unavailable evidence, policy denial, or ambiguous effect settlement.
6. Keep approval, tool authorization, model routing, and write authority outside role prompts.
7. Test success, each hard stop, replay, crash recovery, stale evidence, hostile content, and cleanup.

Hard stop: no unbounded retry, self-approval, hidden budget expansion, or direct side effect is permitted.
