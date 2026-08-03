# Nordrassil — the user-facing product layer

**Status:** active sibling product; workspace foundation, local-model Cookbook,
provider/deployment registry, blind Compare, multi-project management and
persistent project-bound Chat sessions are implemented; sessions now support
star/archive/filter, Documents provides proposal-first Markdown editing, and
the shared responsive product shell now includes a bounded Deep Research
library, launch surface, cited report, inspectable evidence rail and a
read-only Runs / Flow replay surface, sealed bounded single-agent runs with
authenticated checkpoints, and a canonical `eco_teams` Team Studio whose
execution remains fail-closed until signed M5 authority is connected. A
local-model Eval Lab now renders and runs the separate capability battery. The
current visual language is a Nordrassil-specific bio-cyberpunk system rather
than a generic SaaS dashboard. Trace Lab now invokes installed official
assistant clients, records private project traces and turns selected failures
into review-gated memory proposals.

**Snapshot:** 2026-07-26

**Repositories:**

- core: `cyberdid/ecosystem`;
- product: `cyberdid/nordrassil`;
- product head in this snapshot: `101a321`.

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
- project-bound Markdown Documents with explicit AI proposal review;
- project-bound Deep Research runs with explicit budgets, private source CAS
  and citation-shape verification;
- the package-owned Skills catalog;
- a permanent platform/enforcement status.

Direct API routes and model-proposed tools use the same capability state. A
disabled feature cannot be reached by bypassing its UI.

### Responsive product shell

The product no longer presents the implemented slices as a generic technical
dashboard. The source-backed Odysseus review identified the useful interface
grammar — persistent navigation, inline model context, dense operational
surfaces, SVG controls and a real responsive sidebar — without importing its
monolithic application shell or treating visual state as authority.

The first shared shell landed at `85589a8`. Product commit `17c2bc3` replaces
its neutral SaaS treatment with a dependency-free **Nordrassil
bio-cyberpunk** system:

- a root-plane control rail with a hexagonal tree sigil, `ROOT // 01` marker
  and separate Workspace and Knowledge branches;
- a dark canopy canvas with low-opacity grid/scanline layers, luminous green
  active paths and cyan information-flow accents;
- asymmetric clipped surfaces and monospace system runes without replacing
  readable proportional body text;
- persistent project and enforcement context in the top bar;
- a full-height Chat workspace with session rail, readable message measure,
  deployment selector and bounded floating composer;
- shared cards, fields, buttons, warnings, evidence pills and SVG icons across
  Cookbook, Providers, Projects & Files and the remaining foundation views;
- a 390 px off-canvas mobile navigation sheet with scrim and automatic close
  after route selection;
- visible keyboard focus, labelled icon-only attachment/menu controls and
  reduced-motion handling.

The palette preserves semantics: green is active/positive evidence, cyan is
information flow, amber is warning and red is denial. Glow and elevation never
claim authorization. Runs / Flow keeps its `observed` trust and boundary text
visible even though its recorded graph receives the strongest network
treatment.

The Browser acceptance run used live API data, not a mock. Desktop Chat,
Cookbook, Deep Research and a selected 12-node Runs / Flow graph rendered
correctly; all 12 destinations activated their expected panel. At 390 × 844,
Chat and the open navigation sheet rendered without horizontal overflow:
`scrollWidth === clientWidth === 390`. Browser console errors: zero.

This is a usable responsive shell, not a complete PWA or accessibility
certification. The current theme is deliberately dark; a selectable/light
theme, install/offline behavior, persistent density settings and formal
assistive-technology testing remain explicit follow-up work. The product
contract is recorded in
`nordrassil/docs/design-system.md`.

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

### Explicit local A2 execution opt-in

The default behavior remains unchanged: an A2 shell/Python/file-write
allow-candidate is `approval-required` and does not execute on macOS. Commit
`6a07898` adds a separate default-off `execution.local` product capability.

When the operator turns on both the named A2 capability and `execution.local`,
Nordrassil may run the tool as a real local subprocess. The health badge changes
to `local-execute` and states that there is no kernel isolation. This is a
convenience/risk opt-in for the local owner, not the Linux enforced runtime and
not authority for A3 external writes. Email send remains refused by the core.

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
star/unstar, archive/unarchive, active/archived filtering, Markdown export and
delete flows. Important sessions sort first within their state. A browser reload
or process restart rebuilds the same bounded conversation from product-private
state; switching projects does not expose another project's sessions.

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

### Documents

Commits `a29d0ef` and `63b3510` add and harden a writing-first Documents slice:

- private project-bound Markdown records with opaque IDs;
- create/list/open/update/delete and word/byte metrics;
- separate `documents.read` and `documents.write` capabilities;
- AI edit gated by `documents.read` plus `models.invoke`;
- the selected observed deployment returns a complete Markdown proposal into a
  separate review field;
- stored content remains unchanged until the user chooses Apply, which uses the
  normal write path;
- 200-byte title, 1 MiB body, 16,384-character instruction and 200-record list
  bounds;
- `0700` directories, `0600` files, atomic replace and persisted-record
  revalidation;
- project mismatch, unsafe topology, NUL/control data and malformed IDs fail
  closed.

The live browser run created and saved a temporary document, invoked
`gemma4:12b-mlx`, observed the requested revision in the proposal field while
the editor still held the original text, and deleted the temporary record.
Browser console warnings/errors were empty.

This slice is not yet immutable CAS revision history, DOCX/PDF import/render,
collaboration or research-backed citation editing. Those are explicit
non-claims in `nordrassil/docs/document-contract.md`.

### Bounded Deep Research

Commit `96a4263` adds the first usable Research slice:

- a project-bound library of running, complete and failed runs;
- a launch surface with selected observed model, one-to-three round budget and
  two-to-six source budget;
- separate `research.read`, `research.manage` and default-off
  `research.run` capabilities;
- a run also requires independent `web.read` and `models.invoke` grants;
- the model proposes bounded keyword queries and synthesizes fetched text, but
  cannot select a URL, tool, capability or larger budget;
- fixed credential-free Brave/Bing HTML search adapters and public-HTTPS source
  fetch with proxy inheritance disabled;
- normalized source text stored privately by SHA-256, with URL, host, media
  type, byte count, digest, excerpt, retrieval round and `untrusted: true`;
- side-by-side report, citation coverage, search plan and source evidence;
- deterministic recomputation of citation-shape coverage from the report;
- `semanticTruth` remains `not-established` even when citation coverage passes.

The product boundary is explicitly
`product-adapter-not-governed-broker`. It reuses the
`eco_research` URL normalizer and public-address checks, but Nordrassil does not
mint the operator-authored policy or signed capability needed by
`GovernedResearchBroker`. It therefore does not claim that broker's
pinned-address transport, egress policy or signed provenance receipt.

The live run exposed and corrected two provider assumptions. DuckDuckGo's HTML
endpoint returned a bot challenge, and Brave later returned rate limiting/a
larger search page. The final adapter uses bounded Brave with Bing fallback and
a separately bounded 600 KB search response. A real
`gemma4:12b-mlx` run completed with two fetched sources and the recorded search
plan `Python design goals intended uses documentation python.org`.

The model's report ended incomplete and cited only two of four detected claim
lines. Nordrassil did not relabel that as success: the UI showed 50%,
`citation-coverage-incomplete`, and `semanticTruth: not-established`. This is a
valuable negative acceptance result—the retrieval/product flow works while the
model-output gate remains load-bearing.

The slice does not yet provide broker authority, DNS-to-connect pinning,
JavaScript/authenticated/PDF sources, byte-exact quote spans, semantic source
support, background streaming/cancel/retry, automatic memory/document
promotion or multi-agent research. The complete contract is
`nordrassil/docs/research-contract.md`.

### Memory 2.0 — project context without authority

Nordrassil `d181dcd` replaces the original global note-like memory adapter with
one product service over the implemented `eco_memory` graph:

- exact active-project namespace;
- sealed immutable `MemoryRecord`, private content CAS and authenticated journal;
- facts, claims, decisions, constraints, open questions and failed approaches;
- D0–D3 data class, P0–P3 privacy and optional TTL;
- exact content/source/record digests plus supersedes/refutes/conflicts edges;
- exact-text filtering only over records admitted by the core read policy;
- product review annotations bound to an exact record digest and protected by
  a private HMAC;
- additive compaction whose source records remain expandable.

`reviewed` means that a human reviewed the context record; it does not establish
truth. Conflict and expiry are derived states, and every product item reports
`semanticTruth: not-established`. Chat `memory_search` and `memory_add` now use
the same active-project service as the UI.

Verification: 5 focused Memory tests cover project isolation, provenance, TTL,
conflict state, review tamper rejection, separate read/write grants and
reversible compaction. The full Nordrassil suite is 90/90.

### Bounded Agent Runs — composed context, gateway-owned authority

Nordrassil `28faa1b` adds the first usable single-agent execution surface:

- project-bound Agent run library and launcher;
- explicit observed provider/model selection;
- verified `eco_skills` records with transitive dependencies, exact content and
  registry digests, revoked-skill rejection and an instruction-byte budget;
- optional reviewed-only active-project memory; proposed/conflicted/expired/
  rejected records never enter model context;
- exact tool proposal allowlist and capability snapshot;
- maximum steps, tool calls, wall-clock seconds and output tokens reserved per
  model request;
- result, stop reason, checkpoint counters, sealed manifest and full runtime
  event chain in the operator UI.

The architectural boundary is deliberate. `eco_loops` currently executes only
deterministic no-effect/report-only profiles, so Nordrassil does not claim that
an LLM agent is executed by `LoopEngine`. Each run embeds a canonical,
non-executable `LoopDefinition` outline and its digest. The product adapter
enforces the declared reservations and uses the real gateway plus
`eco_runtime.RunEventChain` for lifecycle truth.

Skill text and memory are placed in an explicitly untrusted context section and
carry no authority. Selecting a tool only makes it visible to the model. A real
adapter runs only after the gateway returns `executable`; otherwise the event
chain records `tool.denied`. A2 still requires its named capability and local
execution opt-in; A3 remains core-refused.

After every accepted event Nordrassil atomically rewrites a private
HMAC-SHA256 envelope. The record is reverified on read, exact project identity
is required and the Flow adapter projects only canonical content-free
`RunEvent` data. This qualifies as authenticated product-journal evidence, not
distributed audit authority or semantic answer truth.

Capabilities are separated:

- `agents.read` is default-on and reads only active-project records;
- `agents.run` is default-off and starts/cancels;
- `models.invoke` remains an independent dependency;
- every selected tool retains its own capability and gateway decision.

Verification: 6 focused tests prove manifest/context binding, reviewed-memory
selection, gateway denial, explicit exhaustion, cancellation precedence,
project isolation, HMAC tamper rejection and authenticated Flow replay. The
complete suite is 96/96; live browser acceptance verified the bio-cyberpunk
launcher, catalogs, bounded controls and visible authority boundary.

Commit `f31155c` adds reconnectable live delivery and exact tool review:

- SSE `afterSequence` replay sends only sealed canonical events and checkpoint
  metadata, then terminates with the run;
- non-executable allow-candidates pause with exact subject, argument and display
  digests;
- approve/deny is recorded as product review with `authorityEffect: none`;
- approve re-evaluates the current gateway, so it cannot make an otherwise
  non-executable proposal run;
- cancel/deadline settles any open tool lifecycle before terminal state.

The existing runtime `ApprovalGrant` is correctly not reused here because its
schema requires an exact `WorkspaceChangeProposal`. A generic tool approval
contract remains a core-first future change.

The exact contract is `nordrassil/docs/agent-run-contract.md`. Crash resume,
generic core approval grants, trusted token/cost observations, team execution,
scheduling and independent result acceptance remain separate slices.

### Team Studio — canonical composition without invented authority

Nordrassil `64d2383` adds an operator-facing team manifest studio over the real
`eco_teams` package:

- the UI catalog is projected from the validated core reference manifests
  `evaluator-optimizer` and `orchestrator-workers`;
- every role is bound to exactly one provider/model/transport already observed
  by the provider registry;
- active project, deadline, delegation edges, actions, data classes, narrowed
  role ceilings and aggregate task/token/cost budgets are sealed into a
  canonical `AgentTeamManifest`;
- the core `seal_record` and `validate_record` functions are used directly;
- product state is HMAC-protected, private and revalidated on read;
- the topology canvas shows roles, deployments, delegation and budget state
  beside the exact canonical manifest.

Capabilities remain separate: `teams.read` reads definitions, `teams.manage`
authors them, and default-off `teams.run` is the potential execution surface.
A valid manifest is not runtime authority. There is currently no connected M5
authority store in Nordrassil, so Run remains blocked with
`NORDRASSIL_TEAM_AUTHORITY_UNAVAILABLE` until a current signed authority
snapshot, matching active access policy and separate `ExecutionAuthorizer`
exist. The product does not use test guards or turn a UI toggle into authority.

Live acceptance created a real project-bound evaluator/optimizer definition
against the observed `gemma4:12b-mlx` deployment and rendered its digest,
bindings and explicit `semanticTruth: not-established` boundary. Five focused
tests cover canonical validation, complete role bindings, HMAC tamper rejection,
project isolation and authority-unavailable refusal; the complete product suite
is 104/104. The detailed contract is
`nordrassil/docs/team-studio-contract.md`.

### Local-model Eval Lab — capability evidence in the product

Nordrassil `cf0be03` turns the corrected `ecosystem-llm-lab` battery at
revision `5c08f18` into a normal operator flow without copying or weakening its
gates:

- choose any installed loopback Ollama models;
- select 1, 3 or 5 fresh-context attempts and any subset of the seven fixed
  scenarios;
- launch/cancel one fixed sibling-lab process;
- inspect the report archive, model score cards, positive/control vote matrix,
  per-attempt real gate codes, output digests, token/latency measurements and
  explicit non-claims.

The seven scenarios cover strict structured output, supplied-skill following,
package-ready skill creation, real provenance-bound memory dependency, narrowed
team authoring, native tool invocation plus returned-fact use, and bounded
planner → analyst → independent-reviewer orchestration. The underlying gates
remain `eco_gsc`, `eco_memory`, `eco_teams` and `eco_loops`; a model never grades
or authorizes itself.

Reliability is explicit. A three-attempt run requires both positive and
dependency-negative arms to reach 2/3; five attempts require 3/5. One attempt is
shown as **smoke only** even when the raw battery says 1/1. Code-path controls
are labelled separately because they prove a deterministic gate property, not
model behavior.

`evals.read` is default-on. `evals.run` is independently default-off and
`models.invoke` remains a separate dependency. The product starts only a fixed
Python/module/argv sequence, passes a minimal environment without inherited
credential variables, accepts only currently installed model IDs and keeps raw
transcripts inside the sibling lab's ignored private state. Product job records
are active-project scoped, mode-0600 and HMAC-sealed.

Live acceptance first rendered the corrected full 3-attempt report:

- `gemma4:12b-mlx`: 3/7 contracts established;
- `gpt-oss:20b`: 5/7 contracts established;
- skill creation and one-shot team authoring remain not established for both.

Then the new runner produced report `battery-20260726T071441Z` for one GPT-OSS
structured-output smoke: positive 1/1, control 1/1, 253 tokens, 8.761 seconds.
The UI correctly labels it smoke-only, not promotion evidence.

Five focused Eval tests plus the complete 109/109 product suite prove fixed
argv/minimal environment, independent route capabilities, input validation
before process start, project isolation, HMAC tamper rejection, bounded report
parsing and transcript-path removal. The product contract is
`nordrassil/docs/eval-lab-contract.md`.

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

- Nordrassil: 99 unit tests pass;
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
- live desktop/mobile Browser checks verify the shared shell, real route
  switching, mobile open/close behavior and 390 px no-overflow condition;
- Documents tests verify private CRUD, bounds, cross-project denial, tampered
  record revalidation, distinct route capabilities and that AI edit is a
  bounded non-autosaving proposal; live browser create/save/propose/delete and
  zero console errors are also observed;
- Research tests verify three independent run grants, separate read/manage
  paths, round/source/request bounds, project isolation, source-CAS privacy and
  tamper denial, search-result parsers, safe target rejection, deletion and
  incomplete/unknown citation handling;
- live Research proof verifies default-off denial, explicit opt-in, real public
  search/fetch, two source cards, digest/excerpt display, saved search plan and
  a 50% incomplete citation result from the selected local model; the temporary
  run grant was disabled afterward;
- Agent tests verify immutable composition, reviewed-memory filtering,
  gateway-only tool execution, explicit budget exhaustion, cancellation
  precedence, HMAC tamper denial, project isolation and authenticated Flow
  replay; the live launcher renders observed models, verified skills, tool
  allowlist and all hard-stop controls;
- live SSE replay from cursor 5 returned only canonical events 6–7 and the
  terminal checkpoint; the mixed Flow library simultaneously listed one
  authenticated Agent run and three observed Research runs after an
  epoch/RFC3339 sort regression was found and fixed;
- JavaScript parsing, Python compilation and whitespace checks pass.

### Runs / Flow — Agent Flow grammar over ecosystem evidence

The `patoles/agent-flow` review confirmed that a node/edge canvas, selectable
step inspector and visible execution history are useful product primitives.
What Nordrassil must not import is browser-owned orchestration truth: moving a
node, drawing an edge or showing a green badge cannot create a core plan,
handoff, approval or successful event.

Slice 1 therefore starts from the opposite direction:

```text
recorded run evidence
→ deterministic ecosystem FlowProjection
→ Nordrassil read-only graph
```

The core now has:

- canonical A0 `observability.flow.read`;
- strict `flow.ai.ecosystem/v1alpha1` `FlowProjection`;
- explicit `authenticated`, `validated` and `observed` trust tiers;
- content-free nodes/edges, derived summary and semantic record digest;
- deterministic JSON replay with fail-closed tamper, unknown-field, sequence,
  duplicate/dangling-edge and summary validation;
- no prompt, output, path, credential or authorization fields.

Nordrassil `6424de5`, with dependency-test follow-up `728dd17`, adds:

- separate default-on `runs.read` in capability-state v6;
- `GET /api/flows` and `GET /api/flows/{run_id}`;
- a Runs library, replay graph, selected-step inspector, integrity digest and
  evidence timeline;
- real projection of stored Deep Research `search/open/find/answer` steps;
- truthful `observed · product-observation` and
  `product-research-not-governed-broker` labels;
- no Resume, Retry, Cancel, Execute or graph-authoring controls.

Nordrassil `28faa1b` extends the same observer with real Agent `RunEvent`
chains. Their product journal is HMAC-authenticated and the runtime reducer has
already validated producer capability, issuer, sequence, chain head, lifecycle
and exact tool subject binding. Objective, result, memory, skill bytes,
arguments and returned tool content remain outside Flow.

Live acceptance used existing `ecosystem` project data: three runs were listed;
one rendered 12 nodes, 11 edges and 12 timeline steps with zero console errors.
At 390 × 844 the document width remained bounded and the graph used its own
scroll surface. The 85-test Nordrassil suite is green, including a direct
dependency test for the independent `runs.read` grant.

This is replay, not a control plane. Authenticated
Runtime/Orchestration/Loop/Team execution adapters, real handoff events and
team controls remain future slices and must be driven by durable source
records. Agent SSE/reconnect is implemented separately.

The 104 tests are implementation evidence for the current bounded slices. They
do not prove native macOS kernel isolation, remote provider conformance,
production multi-user security or completion of the full product.

## Honest completion state

| Flow | State |
|---|---|
| Core-gated Chat | persistent sessions, star/archive/filter and bounded UTF-8 attachments working; search and binary extraction remain |
| Capabilities / Files / Memory / Notes / Skills | Memory 2.0 plus the remaining foundation working; skill authoring and richer artifact flows remain |
| Blind Compare | working local slice; rubric/routing gate remains |
| Cookbook / local models | working local lifecycle slice; remote server lifecycle and benchmarked fit remain |
| Providers / deployments | registry, probes, native Ollama and OpenAI Chat working; semantic conformance, remote lifecycle and Triton model adapters remain |
| Projects / Git workspaces | working local slice |
| Responsive shell / accessibility | Nordrassil bio-cyberpunk desktop and 390 px shell, focus and reduced motion working; PWA, selectable/light themes and formal assistive-tech audit remain |
| Localisation | Ukrainian UI with an EN/УКР switcher working (~430 entries, persisted, lossless switch back); contract values and conversation data stay exact by design; further languages and backend-supplied strings that are not yet in the dictionary remain |
| Host tool discovery | PATH plus a fixed allowlist of standard install directories, so uv/pipx/Homebrew installs are seen without restarting the server from a login shell; Windows/other layouts and a user-configurable search path remain |
| Install feedback | a finished Cookbook job re-probes and refreshes the view in place; progress streaming, per-job notifications and failure remediation hints remain |
| Cookbook responsiveness | dependency probes cached for 30 s with an explicit rescan, version probe capped at 1 s, visible scanning state; background/warm probing and a persistent cache remain |
| In-app dialogs | confirm/prompt replaced by a translatable in-app modal after native dialogs were found suppressed in embedded browsers; toast/undo affordances remain |
| Documents | proposal-first project Markdown editor working; revisions/CAS, import/render/export and research citations remain |
| Deep Research | bounded project library/report/evidence slice working; governed broker authority, pinned transport, semantic evidence gate and background job lifecycle remain |
| Runs / Flow | read-only observed Research plus authenticated Agent replay working; Agent SSE/reconnect works, Loop/Team ingestion remains |
| Agents / teams / scheduled tasks | bounded single-agent launcher, live events, exact non-authorizing review and canonical Team Studio working; signed M5 team execution, generic core approval, crash resume and scheduler remain |
| Local-model Eval Lab | fixed loopback runner, progress/cancel, sanitized report archive, vote matrix and attempt evidence working; report remains evidence, never deployment authority |
| Email / Calendar / MCP | planned; credentials stay broker-owned and writes require approval |
| Auth / backup | planned |

The complete live feature inventory is maintained in
`nordrassil/docs/feature-matrix.md`.

## Next delivery order

1. Completed: local/LAN/remote provider registry, transport probes, runtime
   profiles and native Ollama/OpenAI-compatible Chat selection.
2. Completed: session star/archive/filter and proposal-first Markdown
   Documents.
3. Completed: bounded product Deep Research with default-off run, explicit
   budgets, private untrusted source CAS and citation-shape gate; governed
   broker integration and semantic evidence remain.
4. Completed: read-only Runs / Flow with deterministic content-free
   projection and observed Research replay.
5. Completed: project-scoped Memory 2.0 with provenance, lifecycle filters,
   conflict display and reversible compaction.
6. Completed: bounded Agent Run launcher with sealed skills/memory/tools,
   budgets, HMAC checkpoints and authenticated Flow replay.
7. Completed: after-sequence live event stream, exact non-authorizing tool
   review and gateway re-evaluation.
8. Completed for authoring/inspection: canonical Team Studio with observed role
   deployments, delegation graph and aggregate budgets. Execution stays blocked
   until current signed M5 authority and an `ExecutionAuthorizer` are connected.
9. Completed: local-model Eval Lab for skills, memory, tools, agent/team
   authoring and bounded orchestration, including self-consistency controls.
10. Next: versioned Documents with exact research citations, immutable revisions,
   render/import/export and promotion receipts.
11. Tasks, MCP, email/calendar and other external connectors with action-point
   approvals.
12. Authentication, backup/import/export, PWA/mobile and accessibility.

Each slice is done only when it has a usable UI/API, a named core or adapter
boundary, positive and negative tests, a dependency test, provenance and an
honest enforcement label.

## First project evaluation campaign

The first controlled project test is now implemented end to end across four
separately versioned repositories:

| Component | Revision at pilot | Role |
|---|---|---|
| `ecosystem` | `5b030e4` | package-owned `release-evidence-audit` skill and canonical first-project evaluation contract |
| `ecosystem-llm-lab` | `a80c9d1` | immutable campaign, hidden oracle, deterministic seeds, semantic gates and sanitized evidence |
| `nordrassil` | `5591144` | battery/campaign UI, active-workspace binding, safe-profile admission, fixed runner and bounded failure codes |
| `nordrassil-release-evidence-audit` | `8e506a6` | clean synthetic Git fixture with canonical/stale/clean/hostile evidence and one deliberate code defect |

`release-evidence-audit-v1` tests five real product compositions:

1. repository-tool dependency;
2. package-owned skill dependency;
3. reviewed memory dependency;
4. prompt-injection resistance with a denied shell proposal;
5. composite tool + skill + memory behavior.

Each scenario has a positive and ablated control arm. Campaign identity binds
the clean fixture and exact code revisions, full Ollama blob digest, runtime
observation, skill/gate/oracle/capability/evidence digests, budgets and
deterministic per-call seeds. Raw prompts, results, memory markers and tool
content stay in mode-0700 lab state. Public reports contain identities, hashes,
votes, usage and code-owned reason codes only.

Nordrassil now exposes an explicit **Apply safe campaign profile** action and a
separate **Restore previous profile**. The prior operator grants are backed up
privately; the applied profile contains only the read/inference/evaluation
accesses needed to inspect and launch the test. This UI profile is still not
runner authority: the lab constructs its own exact read-only capability
snapshot and the gateway disposes every tool proposal.

### Live smoke evidence

The first final smoke ran through the Nordrassil API on 2026-07-26:

- report: `campaign-20260726T083025Z`;
- model: `gpt-oss:20b`;
- scenario: `project-tool-use`;
- attempts: 1 per arm, explicitly **smoke only**;
- system boundary: held;
- control: 1/1, `LAB_CAMPAIGN_TOOL_DEPENDENCY_CONFIRMED`;
- positive: 0/1, `LAB_CAMPAIGN_AGENT_NOT_SUCCEEDED`;
- aggregate: `LAB_POSITIVE_MAJORITY_NOT_ESTABLISHED`.

The positive arm proposed `read_repository` three times. The bounded agent
executed two calls and stopped at `ECO_AGENT_TOOL_BUDGET_EXHAUSTED`; no final
answer was accepted. The no-tool control correctly avoided fabricating the
fixture fact. The budget was not changed after observing the result and no
hidden retry was performed. This proves the project campaign, negative-control
and reporting path, not the model capability.

The pilot also found two harness integration defects before the final report:
byte-exact oracle text had been line-wrapped in two fixture files, and the
product initially projected only a generic process exit. The fixture was fixed
in explicit commits; Nordrassil now accepts only a bounded
`LAB_[A-Z0-9_]+` child reason code and never copies arbitrary subprocess text
into public job state.

Verification before the pilot:

- Nordrassil: 110/110 tests;
- project campaign lab: 14/14 tests;
- new skill/registry slice: 24/24 focused tests;
- `eco validate`, `eco render --check`, `eco doctor` and 34/34 skill
  projections are clean;
- all four repositories were clean and pushed before inference.

Remaining before a promotion-quality comparison: run all five scenarios with
three attempts per arm and counterbalanced model order; preserve the one-shot
smoke as historical evidence; compare per-scenario votes and usage; do not
interpret macOS execution as Linux `openat2`/Landlock proof or a passing report
as deployment authority.

## Single-operator root testing and runtime lifecycle correction

Nordrassil revision `e080cbe` preserves **Superuser** as an intentional
single-operator test mode. It is the owner's root escape hatch, not a production
role and not a claim that the ecosystem core granted broader authority.
Superuser may enable every product capability and dispatch every mapped tool,
including A2 local execution and tools the core denied. The underlying core
verdict and code remain unchanged in the event; every dispatch caused by this
mode is now explicitly recorded as `superuser-override` with
`operator-superuser` attribution. Unmapped tools still fail closed.

Tool lifecycle evidence now distinguishes:

- `not-dispatched`: the adapter was never entered;
- `succeeded`: the adapter returned successfully;
- `unknown-after-dispatch`: the adapter raised after entry, so a partial side
  effect cannot be ruled out.

Raw exception types, local paths, provider responses and secret-bearing messages
are no longer copied into model context. The model receives only the stable
`NORDRASSIL_TOOL_EXECUTION_FAILED` code and bounded outcome wording.

The Cookbook runtime catalog now keeps five observations separate:

1. host compatibility;
2. runtime installation;
3. downloader readiness;
4. downloaded artifact state;
5. serve readiness.

An artifact can therefore be downloaded for another host even when the current
Mac cannot serve it. `runnableHere` is true only when the artifact is installed,
the runtime and host are ready, and the fit check does not reject it. Ollama,
Hugging Face and NVIDIA NIM use distinct typed, argv-only plans with an explicit
plan-bound confirmation and `shell=False`.

The NIM catalog pins the current certified model-specific release `2.0.8` for
Llama 3.1 8B and Llama 3.3 70B. It requires an externally authenticated Docker
or Podman client; Nordrassil does not store the NGC credential. NIM fit values
are explicitly GPU-memory envelopes, not container download sizes. The 8B entry
uses the documented minimum 24 GB GPU class, while 70B remains a multi-GPU
deployment whose actual profile depends on precision and tensor parallelism.
Sources: [NVIDIA prerequisites](https://docs.nvidia.com/nim/large-language-models/latest/get-started/prerequisites.html),
[support matrix](https://docs.nvidia.com/nim/large-language-models/latest/support-matrix.html)
and [release notes](https://docs.nvidia.com/nim/large-language-models/latest/about-nim-llm/release-notes.html).

### Claude, Codex and GitHub Copilot integration boundary

API access and account login are different integration classes:

| Product | Official access | Nordrassil at `e080cbe` | Correct next adapter |
|---|---|---|---|
| Claude | Anthropic API key, or Claude Code account login on an eligible plan | no native Anthropic Messages transport and no Claude Code client adapter | native API transport or official Claude Code process/agent protocol |
| Codex | OpenAI API key, or ChatGPT sign-in through the official Codex client | no first-class OpenAI hosted profile and no Codex client adapter | OpenAI API profile or Codex CLI/app-server adapter |
| GitHub Copilot | Copilot CLI OAuth/device login, supported token sources, or BYOK | no Copilot CLI/ACP adapter | official Copilot CLI programmatic/ACP adapter |

Nordrassil must not read browser cookies, Keychain entries or cached OAuth token
files from another client. For account-based use, the official CLI owns login
and secure token storage; Nordrassil communicates through its documented
process protocol. For API use, the provider adapter receives only a typed
`env:VARIABLE` reference at its boundary. A consumer subscription is never
silently treated as generic API entitlement.

Verification for revision `e080cbe`:

- full Nordrassil suite: 128/128;
- direct Cookbook suite: 16/16;
- Python compilation, inline JavaScript compilation and `git diff --check`:
  clean;
- live loopback API observed the corrected runtime/readiness projection.

## Official client adapters, Trace Lab and reviewed learning

Nordrassil revision `101a321` implements the missing account-login adapter
class rather than pretending every subscription is an API key.

The **Trace Lab** detects the official Claude Code, Codex and GitHub Copilot
clients, reports sanitized installation/authentication state, and launches a
selected client in the active project using a fixed no-shell argv. Each client
offers `read-only`, `workspace-write` and the owner's explicit `superuser`
mode. Turn count, deadline, model identifier, prompt size and captured output
have hard limits.

Authentication remains client-owned:

- Claude Code owns Claude account/API authentication;
- Codex owns ChatGPT sign-in or OpenAI API-key authentication;
- Copilot CLI owns GitHub OAuth/device/token/BYOK authentication.

Nordrassil does not read cookies, Keychain items or cached token files. A
successful login is also not inserted into canonical
`.ai/deployments.yaml`: it proves a usable local client adapter, not model
identity or semantic deployment conformance.

Every official-client run and every Nordrassil Chat turn now receives a
project-private HMAC trace containing bounded input, model/client events,
gateway tool decisions, results, stderr, stable failure codes, timing, usage
and lifecycle state. Public lists are content-free; private trace bytes require
`audit.read`. Environment-secret values, bearer credentials and common
credential assignments are redacted before persistence. Symlink/hardlink,
tamper, cross-project, terminal-rewrite and size-limit violations fail closed.

The learning path is deliberately review-gated:

```text
trace → bounded untrusted analysis → proposed memory → human review
```

Trace analysis has no tools and requires `audit.read`, `learning.analyze`,
`memory.write` and `models.invoke`. Its lesson separates evidence, hypotheses,
failed approach, prevention, next verification and uncertainty. The result is
always `proposed`; it cannot retrieve itself, authorize an action or change
policy until a human marks the memory reviewed.

Existing Agents, Deep Research, Eval Lab and Cookbook records retain their
specialized authenticated evidence stores. Trace Lab currently provides the
unified analyzer for Chat/client traces; a cross-surface read-only index is a
follow-up projection, not a reason to discard those richer records.

Live verification on 2026-07-26 found:

- Codex `0.146.0-alpha.3.1` installed and authenticated through its official
  account session;
- Claude Code and Copilot CLI not installed on this Mac;
- a live Codex Superuser smoke returned the exact requested sentinel;
- four JSONL events, exit code, duration, token usage and private output were
  recorded;
- the public trace projection exposed no prompt/output;
- full Nordrassil suite 139/139, focused trace/client/security suite 18/18,
  Python/JavaScript compilation and diff checks green.

The normative product/core boundary and hard limits are recorded in
`docs/architecture/official-client-observability.md` and
`nordrassil/docs/client-adapter-observability-contract.md`.

## Autopilot — the concept layer, written for people who do not know the concepts

The product exposed every concept and required the operator to know all of them.
Eight sub-tasks closed that gap; the goal, its objective done-condition and its
decomposition are recorded in `nordrassil/docs/autopilot-goal.md`.

| Surface | Contract | What it does | What it refuses |
| --- | --- | --- | --- |
| Autopilot scopes | `autopilot-scope-contract.md` | three operator switches — `install`, `author`, `run` — all off by default | unrestricted mode never grants them; a granted scope whose prerequisites are off reports itself ineffective and names what it waits for |
| Project brief | `project-brief-contract.md` | a structural tier that opens no file, and a shared tier reading the README heading/excerpt and manifest name/description | consent must name the exact structural digest that was shown; a stale share is reported stale, never reused |
| Concept synthesis | `concept-synthesis-contract.md` | candidate memory, document, skill, agent and team, each named with the validator that passed it | a candidate failing validation is rejected, not offered; a team with no observed deployment is not bound to an invented one |
| Capability broker | `capability-broker-contract.md` | searches tools and skills for a stated task; writes the missing skill | authors skills, never tools; an authored skill is project-scoped and `registryPromotion: not-earned` |
| Provisioner | `provisioning-contract.md` | runs readiness gaps as ordered, typed, allowlisted Cookbook plans | a failed step halts the run; a gap with no typed plan is recorded, not dropped |
| Autopilot loop | `autopilot-loop-contract.md` | understand → resolve → assemble → gate → record, one stage per call | prepares and asks, never dispatches; the intent is immutable for the run |

**Verification.** `docs/research/2026-08-03-autopilot-cold-start-verification-claude.md`
records the dependency-method result on a synthetic UAV-navigation fixture: with
the scopes on, one memory record, one project document and one authored skill
whose verification step names the project's own test command; with the same
capabilities and the scopes off, the identical run halts at `resolve` and
produces nothing; with `execution.superuser` on and the scopes off, still
nothing. 322 tests pass.

**Honest limit.** The loop authors and gates the concept layer; it does not yet
carry a task to completion. Execution remains the existing agent-run path with
its own budgets and its own gateway disposal.
