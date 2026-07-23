# Live capability battery: tool-use, memory, skills, agents

**Date:** 2026-07-23
**Author:** Claude (Fable 5), Claude Code
**Status:** working-session record; live capability characterization, not a benchmark
**Host:** macOS, Ollama serving `gemma4:12b-mlx` and `gpt-oss:20b`, through raw loopback + the project's extraction/reliability helpers

## Question

Before the enforced runtime exists (Linux/WSL), can two unknown local models actually perform the agentic capabilities the ecosystem needs — call tools, use memory, follow skills, write skills, write agents, and select the right one — with the project's contracts acting as objective validators? All of this is WSL-independent (model calls are cross-platform HTTP; the gates are deterministic).

## Result — both models capable across all six

| Capability | Validator | gemma4:12b-mlx | gpt-oss:20b |
|---|---|---|---|
| **Tool-use** (native function calling) | valid `tool_call` name + args vs schema | ✅ `get_weather{city:"Paris"}` | ✅ |
| **Skill-follow** | byte-exact verbatim quote is a substring of the source | ✅ | ✅ |
| **Memory-ground** | answers from provided facts; replies "not available" when absent | ✅ ground + refuse | ✅ ground + refuse |
| **Skill-write** | the real GSC gate (structure, narrowing, secrets, hard-stop) | ✅ ADMISSIBLE | ✅ ADMISSIBLE |
| **Agent-write** | proposed role: id kebab, capabilities ⊆ allowed, budget ≤ team | ✅ (with an explicit id prompt) | ✅ |
| **Select** | chosen skill equals the expected one for the task | ✅ 3/3 | ✅ 3/3 |

Both unknown local models perform every agentic capability. The project's contracts —
the GSC gate, the byte-exact quote check, team-budget narrowing, schema validation — act
as the objective judges of each output, exactly as an unknown R&D team would need.

## Operational findings

- **Memory refusal works.** Instructed to answer only from provided facts, both models
  answered a known question from memory and returned "not available" for an absent one —
  no hallucinated budget number. Grounding + refusal both hold.
- **Byte-exact quoting works.** Both produced a quote that is a character-for-character
  substring of the source, satisfying the M6 source-review gate's hardest rule.
- **gemma's one rough edge is structural completeness, not capability.** Its first
  agent-write omitted the required `id` field (caps and budget were already valid and
  within bounds). With an explicit "id is REQUIRED, kebab-case" prompt it produced a
  complete, valid role (`security-audit-summarizer`). This matches the whole session's
  pattern: gemma needs more explicit prompting for strict structure, but is capable.
- **Selection is reliable.** Both models routed all three tasks to the correct skill
  (fact-check → source-review-evidence, hourly check → bounded-loop-authoring, edit
  contracts → ecosystem-contract-change).

## What this does not claim

- Not a quality benchmark: one or a few scenarios per capability, temperature 0, one host.
- Not the enforced pipeline: the model calls and gates ran cross-platform; policy/broker/
  audit and multi-step live team execution remain Linux/WSL and untested here.
- Live driver scripts live in the session scratchpad and are not committed.

## Next probes (still WSL-independent)

- Multi-step tool use (a chain of tool calls with intermediate results).
- Live agent-team composition (several proposed roles coordinating on one objective).
- Adversarial robustness: an untrusted source that tries to inject an instruction, and
  whether the model keeps it as data (the UNTRUSTED-CONTENT boundary).
