---
name: task-decomposition
description: Split a complex task into bounded sub-tasks with explicit data edges so any model can complete it reliably.
---
<!-- eco-skills:managed surface="portable" registry="72149b048438ccfbd104239d5586ee78a72386f7692ad2e77f1ab6131545bde4" skill="task-decomposition" -->


# Task decomposition

Use this workflow when a single request is too large for one reliable pass — the failure mode where a model takes shortcuts, loses the thread, and returns a half-finished result.

1. State the one overall goal and its objective done-condition before decomposing.
2. Break the goal into sub-tasks, each with one bounded input, one bounded output, and exactly one responsibility.
3. Draw an edge between two sub-tasks only when the later one actually consumes the earlier one's output; "and then" without data flow is not an edge.
4. Mark which sub-tasks are independent (may run in parallel) and which must wait for a specific upstream output.
5. Give each sub-task a validated output shape so the next consumer does not have to guess.
6. Keep the decomposition itself explicit and reviewable; do not let the model expand scope silently mid-run.
7. Recompose only at a node that genuinely needs every prior result together; otherwise pass results along without a barrier.

Hard stop: no sub-task may exceed the goal's authority, budget, or policy; decomposition organizes work, it never grants new capability.
