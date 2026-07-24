# Nordrassil — the user-facing product layer

**Status:** active sibling product; workspace foundation, local-model Cookbook,
provider/deployment registry, blind Compare, multi-project management and
persistent project-bound Chat sessions are implemented.

**Snapshot:** 2026-07-24

**Repositories:**

- core: `cyberdid/ecosystem`;
- product: `cyberdid/nordrassil`;
- product head in this snapshot: `dc7c781`.

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

The local Odysseus source at
`/Users/helenshkirenko/Downloads/odysseus-dev` was inspected rather than
inferred from screenshots: 73 Python route files with 465 HTTP/WebSocket route
decorators, 152 JavaScript files with 128,328 lines, 58,669 Python lines across
`src` and `core`, and 737 test files with 4,076 test functions. Its local
`LICENSE` is MIT. These are orientation counts, not a claim that every branch
has been ported.

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

### Providers and deployments

The Odysseus endpoint/model-picker workflow is now adapted through a stricter
product boundary:

- private create/edit/delete endpoint registry;
- built-in native Ollama deployment;
- grouped provider/model picker in Chat;
- explicit default provider/model pair;
- runtime profiles for Ollama, llama.cpp, MLX-LM, vLLM-Metal, LM Studio, vLLM,
  SGLang, Hugging Face TGI, NVIDIA NIM and NVIDIA Triton;
- native Ollama and OpenAI-compatible Chat adapters;
- transport-specific probe paths for Ollama, OpenAI/NIM and Triton KServe V2;
- private observations and observed model IDs;
- separate `providers.read`, `providers.manage` and default-off
  `providers.probe` capabilities.

Network zones are explicit:

| Zone | Accepted endpoint |
|---|---|
| local | loopback hostname or address only |
| private LAN | literal RFC1918 or IPv6 ULA address; no DNS rebinding surface |
| remote | HTTPS only |

Provider URLs reject userinfo, query and fragments. Credential values are never
stored; the only accepted form is `env:VARIABLE`, resolved at the adapter
boundary. Probe and Chat disable environment proxies and revalidate redirects
against the original zone.

A successful probe proves transport reachability and a parseable model catalog
only. `tools`, `structuredOutput`, `vision` and `embeddings` remain `unknown`
until independent per-deployment conformance exists. In particular, Triton is
shown as a KServe V2 model platform and can expose health/repository
observations, but it is not sent to Chat as if KServe were OpenAI-compatible.

The live acceptance proof established two real paths on this Mac:

1. native `ollama-native` probe and Chat returned
   `provider-registry-ok`;
2. a separately registered `http://127.0.0.1:11434/v1` endpoint was probed and
   returned `openai-adapter-ok` through the OpenAI-compatible adapter;
3. both observed `gemma4:12b-mlx` and `gpt-oss:20b`;
4. semantic labels remained `unknown`;
5. the temporary `providers.probe` grant was turned off after the run.

The provider record and observations remain ignored product-private runtime
state. The complete record, data-edge, probe and non-claim contract is in
`nordrassil/docs/provider-deployment-contract.md`.

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

### Persistent Chat sessions and provenance-bound attachments

Chat now has private, project-bound sessions with create, switch, rename,
Markdown export and delete flows. A browser reload or process restart rebuilds
the same bounded conversation from product-private state; switching projects
does not expose another project's sessions.

The first attachment slice accepts only explicitly selected UTF-8 text,
Markdown, JSON, XML, YAML, CSV/TSV, Python and JavaScript files. The browser
sends a display filename, media type and bytes — never a server-side path.
Ingestion stores the bytes in a private SHA-256 content-addressed store and
binds the attachment metadata to the exact project and session. Before model
context is rebuilt, Nordrassil verifies the object size and digest again and
labels its contents as untrusted attachment data.

The enforced bounds are:

| Boundary | Limit |
|---|---:|
| One attachment | 256 KiB |
| Attachments selected for one message | 5 |
| Combined attachment model context | 512 KiB |
| Attachments retained by one session | 50 |
| One user message | 64 KiB UTF-8 |
| Model history | 40 messages / 256 KiB |
| Persisted messages | 400 |

`sessions.read`, `sessions.manage` and `attachments.upload` are separate
operator capabilities. Negative tests reject cross-project and cross-session
references, modified CAS objects, symlinked state roots, path-like filenames,
binary/unsupported media, malformed base64, oversize content and capability
bypass. Images, audio, PDF extraction, OCR, session search and archive remain
explicitly outside this slice.

The data graph and done-condition are recorded in
`nordrassil/docs/session-attachment-contract.md`.

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

- Nordrassil: 57 unit tests pass;
- `eco validate`: pass;
- `eco render --check`: pass;
- live browser proof: allowed repository read and denied shell execution both
  observed through the real gateway;
- live browser proof: a `README.md` attachment survived reload with its
  SHA-256 provenance chip, and `gemma4:12b-mlx` returned the exact project name
  from those verified bytes;
- Cookbook mutation tests verify private plan state, identifier/path bounds,
  explicit confirmation and `shell=False`;
- workspace tests verify private registry permissions, root confinement,
  symlink resolution, per-request root pinning, safe clone plans and
  capability-gated import/folder creation;
- session tests verify private CRUD/export, actual history dependency, digest
  rehydration, project/session isolation, state topology, content limits and
  distinct capability gates.
- provider tests verify private permissions, CRUD, built-in immutability,
  revalidation of tampered state, URL/zone/transport rejection, plaintext
  secret rejection, probe observations, default persistence, secret
  non-persistence, OpenAI tool schema and capability gates;
- JavaScript parsing, Python compilation and whitespace checks pass.

The 57 tests are implementation evidence for the current bounded slices. They
do not prove native macOS kernel isolation, remote provider conformance,
production multi-user security or completion of the full product.

## Honest completion state

| Flow | State |
|---|---|
| Core-gated Chat | persistent sessions and bounded UTF-8 attachments working; search/archive and binary extraction remain |
| Capabilities / Files / Memory / Notes / Skills | working foundation; authoring and richer artifact flows remain |
| Blind Compare | working local slice; rubric/routing gate remains |
| Cookbook / local models | working local lifecycle slice; remote server lifecycle and benchmarked fit remain |
| Providers / deployments | registry, probes, native Ollama and OpenAI Chat working; semantic conformance, remote lifecycle and Triton model adapters remain |
| Projects / Git workspaces | working local slice |
| Deep Research / Documents | planned |
| Agents / teams / scheduled tasks | planned; must use bounded loops and evaluated delegation |
| Email / Calendar / MCP | planned; credentials stay broker-owned and writes require approval |
| Auth / backup / PWA / accessibility | planned |

The complete live feature inventory is maintained in
`nordrassil/docs/feature-matrix.md`.

## Next delivery order

1. Completed: local/LAN/remote provider registry, transport probes, runtime
   profiles and native Ollama/OpenAI-compatible Chat selection.
2. Memory 2.0: provenance-visible namespaces, search, fact/lesson lifecycle,
   reviewed promotion, conflict display and reversible compaction.
3. Governed Research and versioned Documents with exact citations and proposed
   diffs.
4. Bounded Agent runs, skill repair loops and evaluated team orchestration.
5. Tasks, MCP, email/calendar and other external connectors with action-point
   approvals.
6. Authentication, backup/import/export, PWA/mobile and accessibility.

Each slice is done only when it has a usable UI/API, a named core or adapter
boundary, positive and negative tests, a dependency test, provenance and an
honest enforcement label.
