---
name: self-consistency-verification
description: Raise reliability by sampling independent attempts and requiring majority agreement before a result is accepted.
---
<!-- eco-skills:managed surface="portable" registry="4a823fe6b3a2e49a646ac0ec0cbdb15bc08b1749660972cc91123f300e4c2680" skill="self-consistency-verification" -->


# Self-consistency verification

Use this workflow for a result whose correctness matters more than its latency, where a single pass can look right but be wrong.

1. State the exact claim or output whose reliability must be established, and the objective check that decides agreement.
2. Produce N independent attempts, each from a fresh context so they cannot copy one another's reasoning.
3. For a verification task, prompt each independent attempt to *refute* the result, defaulting to "not established" when uncertain.
4. Accept the result only when a declared majority of independent attempts agree under the objective check.
5. Prefer diverse lenses over identical repeats when the result can fail in more than one way — correctness, safety, reproducibility.
6. Record the vote and the disagreement, not just the accepted answer, so a later reviewer can see how confidence was reached.
7. On no majority, return "not established" with the reasons — never a confident answer the votes did not support.

Hard stop: the verifier is never the author of the result; agreement is evidence, not authority, and a passing vote never bypasses policy, approval, or a runtime gate.
