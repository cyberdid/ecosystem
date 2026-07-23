# Nordrassil — the user-facing product layer

**Status:** active sibling product; workspace foundation, local-model Cookbook,
blind Compare and multi-project management are implemented.

**Snapshot:** 2026-07-23

**Repositories:**

- core: `cyberdid/ecosystem`;
- product: `cyberdid/nordrassil`;
- product head in this snapshot: `8f4d0c3`.

## Why Nordrassil exists

`ecosystem` is the trusted core: canonical contracts, typed capabilities,
policy decisions, provenance-bound memory, bounded loops, agent-team narrowing,
governed tools and durable evidence. It is intentionally not a normal-user
application.

Nordrassil is the normal-user layer over that core. Its product target is an
Odysseus-class local AI workspace: chat, models, files, projects, comparison,
research, documents, memory, skills, agents, tasks and integrations. Odysseus
is a feature and UX reference, not the authority boundary and not a runtime
dependency.

The defining inversion is:

> The product renders and requests; the core grants or denies.

A model response, prompt, UI toggle, skill, connector or product route may
propose an action. None of them grants permission. Unsupported or unauthorized
actions remain denied even if a model repeatedly asks for them.

## What the Odysseus audit established

The local Odysseus source was inspected rather than inferred from screenshots:
36 route groups, more than 430 HTTP endpoints, over 92,000 frontend lines and
over 37,000 lines in its main Python systems. Its local `LICENSE` is MIT.

Useful patterns to retain:

- complete local-first workflows rather than isolated demos;
- model discovery, endpoint probing and a model Cookbook;
- visible background progress, diagnosis, cancellation and retry;
- sessions, uploads, documents, notes, research and integrations in one place;
- path-confinement and regression testing.

Authority patterns not to inherit:

- free-form shell strings as the execution contract;
- application-local admin booleans or denylists as final authorization;
- prompt text as the security boundary for untrusted content;
- direct model/tool credentials in agent-visible configuration;
- silent memory promotion or context compaction;
- unbounded background agent loops.

The audit also corrected an important product assumption: Odysseus has uploads
and configurable tool roots, but no Codex/IDE-style project registry, native
project-folder picker or Git-clone workspace flow. Nordrassil's project manager
is therefore a new product capability, not a port.

The full source-backed analysis lives in
`nordrassil/docs/odysseus-adoption-audit.md`.

## Product-to-core execution path

```text
human action or model proposal
→ Nordrassil typed request
→ product gateway
→ ecosystem capability/team-access decision
→ deny | approval-required | executable allow
→ bounded adapter or broker execution
→ receipt, provenance and UI event
```

The gateway exposes both whether a request is logically allowed and whether it
is executable under the current platform/runtime. This distinction prevents a
team-access allow-candidate from being presented as complete signed runtime
authority.

The current decision record includes:

- `allowed`;
- `executable`;
- `effective_authorization`;
- `enforcement`;
- `disposition`;
- a code-owned reason code.

## Implemented product slices

### Workspace foundation

The FastAPI browser workspace exposes:

- Chat with a live local model and a visible tool timeline;
- Capabilities with persisted user choices and core-owned denials;
- Files rooted in the active project;
- provenance-labelled Memory;
- Notes;
- the package-owned Skills catalog;
- a permanent platform/enforcement status.

Direct API routes and model-proposed tools use the same capability state. A
disabled feature cannot be reached by bypassing its UI.

### Core-gated chat tools

The live model may propose file reads, shell work or external actions, but each
proposal passes through the gateway. The verified browser path demonstrated:

- an allowed repository read executes and its returned bytes inform the answer;
- a shell request without authority is denied with the core's reason code and
  does not execute;
- A2 shell/Python/file-write allow-candidates remain `approval-required`;
- A3 email send remains hard-denied without an approved connector.

On macOS the badge says `local-described`. It proves that the real decision path
was used, not that Linux `openat2`/Landlock isolation exists on macOS.

### Blind local-model Compare

Compare sends independent requests to selected installed Ollama models. Model
identity stays hidden until explicit Reveal; optional synthesis is labelled
non-authoritative. The current slice is useful for direct comparison, but it is
not yet a canonical `eco_routing` evaluation or an independently gated winner
selection.

### Local Model Cookbook

Cookbook provides the missing operational model layer:

- Apple Silicon hardware scan and memory-based fit estimates;
- installed Ollama model discovery;
- Ollama and Hugging Face cache inventory;
- live Hugging Face catalog search;
- dependency diagnosis;
- bounded inference settings and Chat-model selection;
- download/install/serve planning;
- private job state, progress and logs;
- standalone loopback llama.cpp serving for discovered GGUF files.

Every mutating action is two-step:

1. create and persist a typed plan containing a validated argv vector;
2. confirm the exact plan before execution.

Execution uses `shell=False`. Browser-supplied shell commands are not accepted.
Downloads, dependency installation and server starts have separate capabilities
and are disabled by default.

Current local inventory used for the product proof:

| Item | Observed value |
|---|---|
| Mac | MacBook Pro, Apple M4 Max, 14 CPU cores, 36 GB unified memory |
| Ollama | `0.32.1` |
| Installed model | `gemma4:12b-mlx`, 10.0 GB |
| Installed model | `gpt-oss:20b`, 13 GB |

This inventory is observational, not a capability claim. A model becomes a
governed deployment only after identity and conformance evidence are bound.

### Projects and Files

The multi-project manager supports:

- a private recent-project registry;
- native macOS folder selection;
- manual folder import;
- new project and subfolder creation;
- typed, confirmation-bound Git clone plans;
- project switching;
- Git branch, dirty-state and remote metadata;
- structured file-tree browsing.

The selected project is pinned into each request context and becomes the
confinement root for Files and chat tools. It is not read from a mutable global
halfway through a request. Relative roots, overly broad roots, symlink escapes,
credential-bearing clone URLs, shell syntax, `.git`, `.env`, sensitive
configuration paths and Nordrassil private state are rejected.

## Relationship to the local-LLM experiment

The separate `ecosystem-llm-lab` answers an engineering question: can each
local model actually use memory, follow a skill, author a bounded agent,
request tools and participate in orchestration when the real ecosystem gates
are load-bearing?

Nordrassil answers the product question: can a normal user select those models,
projects and capabilities, observe the decisions, and run the same ideas
without operating the core by hand?

The evidence affects the product design directly:

- one-shot skill and team-manifest authoring is not established for either
  tested model, so authoring must use propose → gate → repair;
- native tool-call emission is valuable evidence, but a returned fact must
  influence the answer before tool-result use is claimed;
- deterministic controls must be labelled as code-path controls, not model
  behavior;
- model output never proves its own authority or completion;
- agent teams remain opt-in until they beat the single-agent baseline for a
  named task.

The detailed correction and proof reports are:

- [Codex lab accuracy review](../docs/research/2026-07-23-codex-lab-accuracy-review-claude.md);
- [live capability battery](../docs/research/2026-07-23-live-capability-battery-ollama-claude.md);
- [memory dependency proof](../docs/research/2026-07-23-real-memory-verification-mini-project-claude.md);
- [skill-follow proof](../docs/research/2026-07-23-skill-follow-verification-real-gate-claude.md);
- [agent-authority proof](../docs/research/2026-07-23-agent-write-verification-authority-gate-claude.md);
- [full memory → skill → agent → gate proof](../docs/research/2026-07-23-full-chain-verification-memory-skill-agent-gate-claude.md).

## Current verification

At this snapshot:

- Nordrassil: 42 unit tests pass;
- `eco validate`: pass;
- `eco render --check`: pass;
- live browser proof: allowed repository read and denied shell execution both
  observed through the real gateway;
- Cookbook mutation tests verify private plan state, identifier/path bounds,
  explicit confirmation and `shell=False`;
- workspace tests verify private registry permissions, root confinement,
  symlink resolution, per-request root pinning, safe clone plans and
  capability-gated import/folder creation.

The 42 tests are implementation evidence for the current bounded slices. They
do not prove native macOS kernel isolation, remote provider conformance,
production multi-user security or completion of the full product.

## Honest completion state

| Flow | State |
|---|---|
| Core-gated Chat | working foundation; sessions and attachments remain |
| Capabilities / Files / Memory / Notes / Skills | working foundation; authoring and richer artifact flows remain |
| Blind Compare | working local slice; rubric/routing gate remains |
| Cookbook / local models | working local slice; vLLM, remote servers and benchmarked fit remain |
| Projects / Git workspaces | working local slice |
| Deep Research / Documents | planned |
| Agents / teams / scheduled tasks | planned; must use bounded loops and evaluated delegation |
| Email / Calendar / MCP | planned; credentials stay broker-owned and writes require approval |
| Auth / backup / PWA / accessibility | planned |

The complete live feature inventory is maintained in
`nordrassil/docs/feature-matrix.md`.

## Next delivery order

1. Persistent sessions and provenance-bound attachments.
2. Local/API-compatible provider registry, probes and conformance labels.
3. Governed Research and versioned Documents with exact citations and proposed
   diffs.
4. Bounded Agent runs, skill repair loops and evaluated team orchestration.
5. Tasks, MCP, email/calendar and other external connectors with action-point
   approvals.
6. Authentication, backup/import/export, PWA/mobile and accessibility.

Each slice is done only when it has a usable UI/API, a named core or adapter
boundary, positive and negative tests, a dependency test, provenance and an
honest enforcement label.
