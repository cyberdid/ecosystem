# Wiki Log

Append-only хронологічний лог операцій. Формат: `## [YYYY-MM-DD] тип | назва`

---

## [2026-07-26] product | Nordrassil canonical Team Studio

- Published Nordrassil product commit `64d2383`.
- Added Team Studio over the real `eco_teams` reference manifests,
  `seal_record` and `validate_record`; the product does not duplicate the
  canonical topology contract.
- Every role requires an exact provider/model binding resolved through the
  observed deployment registry. The sealed project-bound manifest fixes
  delegation, actions, data classes, per-role ceilings and aggregate
  task/token/cost/deadline budgets.
- Added a bio-cyberpunk topology canvas, team library, authority status,
  aggregate metrics and canonical manifest inspector.
- Added independent `teams.read`, `teams.manage` and default-off `teams.run`
  capabilities. A toggle cannot create authority.
- Execution intentionally fails closed with
  `NORDRASSIL_TEAM_AUTHORITY_UNAVAILABLE`: Nordrassil has no connected current
  signed M5 snapshot, matching active access policy or separate
  `ExecutionAuthorizer`. No test guard or simulated multi-model execution is
  presented as real.
- Private team records are HMAC-sealed, active-project scoped and revalidated
  on every read. Cross-project reads and tampering fail closed.
- Verification: 5 focused Team Studio tests, full 104/104 product suite,
  Python compile, whitespace/secret checks and live browser creation of an
  evaluator/optimizer manifest against an observed local deployment.
- Remaining: connect real M5 authority and `TeamCoordinator`, emit
  authenticated handoff/budget/cancel events into Flow, and compare evaluated
  team performance against the single-agent baseline.

## [2026-07-26] product | Nordrassil live Agent events and exact tool review

- Published Nordrassil product commit `f31155c`.
- Added reconnectable SSE over already HMAC-sealed canonical `RunEvent`
  evidence. `after=N` returns only later contiguous events, a checkpoint,
  terminal state and head digest; it excludes objective, result, skill/memory
  bytes, tool arguments and tool output.
- A gateway `allowed` but non-executable proposal now pauses the run with exact
  subject/argument/display digests and expiry. Approve/deny is an
  HMAC-protected product review with `authorityEffect: none`, not a misapplied
  core `ApprovalGrant` (the current canonical grant is bound to
  `WorkspaceChangeProposal`).
- Approve re-evaluates the current gateway. Without a separate executable
  capability/runtime grant the proposal is recorded as
  `ECO_TOOL_REVIEW_NOT_EXECUTABLE`; exact denial is
  `ECO_TOOL_REVIEW_DENIED`.
- Cancellation or deadline while waiting closes the open tool lifecycle before
  the terminal event. Cancel received during a blocking model/tool call is
  rechecked before any success claim.
- Live acceptance found and fixed a mixed-history bug: Research stored epoch
  integers while Agent used RFC3339, causing Flow list sorting to fail.
  Both now normalize to one sort key.
- Verification: full 99/99 Nordrassil suite; real SSE reconnect from sequence 5
  returned only events 6–7 plus terminal checkpoint; live Flow listed one
  authenticated Agent run and three observed Research runs.
- Still unclaimed: generic core approval grant for arbitrary tools, crash
  resume, mid-call pre-emption, distributed stream broker and semantic result
  acceptance.

## [2026-07-26] product | Nordrassil bounded Agent Run launcher

- Published Nordrassil product commit `28faa1b` with a usable project-bound
  Agent launcher over existing ecosystem primitives rather than a second
  prompt-owned runtime.
- Every run seals the objective digest, observed provider/model, exact verified
  skill and registry digests, reviewed-memory bindings, tool allowlist,
  capability snapshot and step/tool/deadline/output-reservation budgets before
  execution.
- The current `eco_loops` engine executes only deterministic no-effect profiles,
  so the model run honestly carries a non-executable canonical
  `LoopDefinition` outline while the product adapter enforces its reservations
  and hard stops.
- Every tool proposal is disposed by the existing gateway. Skill instructions
  and memory are context only and cannot enable tools, capabilities or
  permissions.
- Runtime lifecycle evidence is accepted by `RunEventChain`; every checkpoint
  is atomically HMAC-sealed. Project mismatch and journal tamper fail closed.
  Agent events now replay through Runs / Flow as authenticated external-journal
  evidence without exposing objective, result, memory, skill bytes, arguments
  or tool output.
- Added default-on `agents.read` and separate default-off `agents.run`;
  `models.invoke` and each tool capability remain independent dependencies.
- Verification: 6 focused Agent tests plus the full 96/96 Nordrassil suite,
  Python/JavaScript syntax, whitespace checks and live browser acceptance pass.
  Cancel during a blocking model call is rechecked before success can be
  recorded.
- Explicit non-claims: no crash resume, durable approval-grant protocol,
  trusted observed token/cost telemetry, team delegation, scheduler or
  independent semantic result gate.

## [2026-07-26] product | Nordrassil project-scoped Memory 2.0

- Published product commit `d181dcd` over the existing `eco_memory` sealed
  record, private CAS, HMAC journal, deterministic retrieval and reversible
  compaction primitives.
- Replaced the global note-like adapter with exact active-project namespaces.
  Chat memory tools and the UI now consume the same service.
- Added memory types, D0–D3/P0–P3 labels, TTL, conflict links, provenance
  digests, search/filtering, review state, compaction and source expansion.
- Human review is a content-free HMAC-protected product annotation bound to one
  record digest. It is not semantic truth, policy or authority; every item
  reports `semanticTruth: not-established`.
- Verification: 5 focused Memory tests and the full 90/90 Nordrassil suite,
  compilation, whitespace checks and live desktop UI acceptance pass.
- No embeddings, semantic ranking, automatic promotion, deletion worker,
  distributed storage or memory-derived permission is claimed.

## [2026-07-26] product | Nordrassil bio-cyberpunk interface system

- Replaced the generic neutral shell with a Nordrassil-specific rooted
  intelligence grammar at product commit `17c2bc3`: hexagonal tree sigil,
  root-plane navigation, canopy haze, luminous sap paths, clipped surfaces and
  monospace system runes.
- Preserved semantic status colours and authority text. Visual glow, graph
  emphasis and active state do not promote product observations or authorize
  work.
- Applied the shared system across Chat, Cookbook, Providers, Compare, Deep
  Research, Runs / Flow, Projects & Files, Memory, Documents, Notes, Skills and
  Capabilities without external fonts, images or frontend dependencies.
- Live acceptance: all 12 routes activate the expected panel; desktop Chat,
  Cookbook, Deep Research and a selected 12-node Flow graph render with real
  data; browser console errors are zero.
- At 390 × 844, Chat and the open navigation sheet render with
  `scrollWidth === clientWidth === 390`. Focus and reduced-motion behavior
  remain; complete WCAG, a light/user-selectable theme and PWA are not claimed.
- Verification: 85/85 Nordrassil tests, Python compilation and whitespace
  checks pass.

## [2026-07-26] product | Nordrassil deterministic Runs / Flow replay

- Added canonical A0 `observability.flow.read` and the additive
  `flow.ai.ecosystem/v1alpha1` `FlowProjection` contract.
- The projector produces ordered content-free nodes and edges, explicit source
  trust/boundary, deterministic summary and a semantic digest. Replay calls no
  model/tool/runtime and rejects tamper, unknown fields, broken sequence,
  dangling edges and summary drift.
- Published Nordrassil feature `6424de5` and boundary-test follow-up `728dd17`
  with capability-state v6 `runs.read`, `/api/flows` routes and a responsive
  run library, graph, inspector, integrity card and evidence timeline.
- Real Deep Research history maps recorded `search/open/find/answer` steps but
  excludes query arguments, observations, reports and source content from the
  core projection. The UI displays `observed · product-observation` and
  `product-research-not-governed-broker`.
- Live acceptance listed three project runs; one rendered 12 nodes, 11 edges
  and 12 timeline entries with zero console errors. The 390 × 844 view kept the
  document width bounded and scrolled only inside the graph surface.
- Verification: 85/85 Nordrassil tests (including a direct `runs.read`
  dependency check); 7/7 focused core flow tests, `eco validate`,
  `eco render --check`, `eco doctor`, compilation and diff checks pass.
  Full core regression was attempted on macOS and remains platform-red in the
  pre-existing Linux-only `openat2`/Landlock test class.
- No live stream, authenticated Orchestration/Loop/Team ingestion, inferred
  handoffs, graph-authored execution, Resume or Retry is claimed.

## [2026-07-26] skills | Pinned Microsoft Skills audit and non-promoting importer

- Downloaded and statically reviewed `microsoft/skills` at exact commit
  `4f1db7ec55caf11e3b143c91220bd79a632bc55b` without executing its scripts,
  hooks, MCP servers, installers or eval harness.
- The source is a valuable cookbook but not a drop-in trusted registry: the
  review found 194 regular skill files, stale catalog counts, warning-only eval
  gates, opt-out Azure telemetry, unpinned runtime references, prompt-level
  memory/agent authority and ten broken Microsoft Foundry symlinks.
- Added `eco skills import-plan`: an offline, deterministic, content-free review
  of one exact local Git commit. It reads Git objects rather than working-tree
  bytes, rejects malformed paths/frontmatter/tree modes, never follows
  filesystem symlinks and reports duplicate identities plus bounded execution
  signals.
- Every external candidate remains non-promotable until separate capability,
  test, evidence, owner, adversarial-gate and exact-digest approval steps.
- Live repeated CLI output was byte-identical: plan
  `d09df5b1fe494a00a3de22676a60098b70276710bec150ba1204ffe479a9eb52`,
  1,982 entries, 194 skill files, 186 review-required, 8 blocked, 60 symlinks,
  10 broken symlinks, 10 executables, 8 hook files, 3 strict MCP configs and 5
  unpinned skill runtime references.
- Verification: 28 focused tests, canonical validation, projection drift,
  doctor and diff checks pass. Full macOS regression remains explicitly
  platform-red with the same Linux-only/openat2 class as pristine `HEAD`; all
  six added importer tests pass.
- Full analysis and boundaries:
  [External skills and Microsoft Skills](upstream-skills.md).

## [2026-07-26] product | Nordrassil Deep Research → OpenResearcher-style agentic trajectory

- Elevated Nordrassil Deep Research to the OpenResearcher patterns the ecosystem catalogued
  (`wiki/openresearcher.md`): explicit **search / open / find / answer** primitives, an agentic
  trajectory where the model chooses one action per turn, full trajectory recording (successful
  and failed steps), and retrieval measured separately from reasoning.
- Kept the SSRF-safe boundary: `open` selects one already-vetted search hit by its Hn id — the
  model never supplies a URL, so every fetched address stays public-address-checked. `find` is
  network-free (reads only already-fetched, content-addressed source text). Bounds unchanged
  (`rounds` caps searches, `maxSources` caps opens); citation-coverage verification and the
  untrusted-source discipline are intact; semantic truth stays `not-established`.
- Verified live: a real run searched (9 hits), adapted around failed fetches (kept as failed
  trajectory steps), used `find`, opened three distinct hosts, and produced a cited Canberra
  report with honest 0.5 citation coverage. The UI shows the step timeline and retrieval metrics.
- Remains a product adapter, explicitly not the GovernedResearchBroker. Nordrassil commit
  `da91d37`; 81 tests pass (2 new: trajectory + find).

## [2026-07-24] product | Nordrassil bounded Deep Research and evidence-first design

- Published `cyberdid/nordrassil` commit `96a4263` with a project-bound Deep
  Research library, explicit launch budgets, selected-model context, report
  canvas and side-by-side evidence cards.
- Added separate `research.read`, `research.manage` and default-off
  `research.run`; a run also depends on `web.read` and `models.invoke`.
- Model output may propose a bounded keyword query and synthesize marked
  untrusted source blocks, but it cannot call a tool, select a URL, widen a
  budget, enable a grant or promote output into Memory/Documents.
- Public HTTPS sources are normalized, bounded, stored privately by SHA-256 and
  reverified on read. Cross-project access, local/non-HTTPS targets, unsafe
  state, tampered source objects and unknown citations fail closed.
- Independent live acceptance found real search-provider failures:
  DuckDuckGo returned a bot challenge, while Brave later rate-limited/returned
  larger HTML. The corrected bounded adapter uses Brave with Bing fallback and
  a separate 600 KB search-page limit.
- Final live `gemma4:12b-mlx` proof fetched two sources and rendered their URLs,
  excerpts, round, sizes and digests. The model response was incomplete and
  only 2/4 detected claims were cited, so the deterministic gate correctly
  reported 50%, `citation-coverage-incomplete` and
  `semanticTruth: not-established`.
- `research.run` was returned to off after acceptance. The product explicitly
  does not claim `GovernedResearchBroker` authority, address-pinned transport,
  semantic truth, prompt-injection immunity or background research jobs.
- Verification: 79/79 Nordrassil tests, Python compilation, inline JavaScript
  parse and diff checks pass.

## [2026-07-24] product | Nordrassil local execution, session lifecycle and Documents

- Verified and recorded four published Nordrassil commits:
  `6a07898` adds a separate default-off, visibly unisolated local A2 execution
  opt-in; `bd61204` adds session star/archive/filter; `a29d0ef` adds the
  proposal-first Documents editor; `63b3510` closes its acceptance gaps.
- Documents stores bounded project-bound Markdown records in private state,
  separates read/write/model capabilities and never lets the AI-edit endpoint
  autosave. Apply is an explicit normal write.
- The original feature commit claimed 67 passing tests, but an independent full
  run found one stale capability-migration expectation. The acceptance fix
  updated that specification, added route-level capability tests,
  non-autosave proof, instruction bounds and persisted-record tamper
  revalidation.
- Final verification is 70/70 Nordrassil tests plus Python compilation,
  JavaScript parsing and whitespace checks.
- Live Browser evidence on the restarted current server: create/list/save
  worked; `gemma4:12b-mlx` returned a separate requested proposal while stored
  content remained unchanged; the temporary QA record was deleted; browser
  console errors/warnings were empty.
- Documents does not yet claim immutable revisions/CAS, research citations,
  DOCX/PDF import/render, collaboration or correctness of model edits. The next
  product slice is governed Deep Research.

## [2026-07-24] design | Nordrassil responsive product shell

- Published `cyberdid/nordrassil` commit `85589a8` with a shared interface
  system for every current product view.
- Replaced the generic light admin layout and emoji navigation with a dark
  grouped control rail, semantic light/dark tokens, SVG controls, persistent
  project/enforcement context, clearer operational density and a full-height
  Chat workspace.
- Adapted only the useful Odysseus interaction grammar — persistent workspace
  navigation, inline model context, responsive sidebar and compact operational
  surfaces. The Odysseus application shell and monolithic stylesheet were not
  copied, and UI state did not become authority.
- Added a real off-canvas mobile navigation pattern, labelled icon-only
  controls, `:focus-visible` treatment and reduced-motion behavior.
- Live Browser verification covered desktop Chat, Providers and Projects &
  Files plus 390 × 844 Chat, open navigation and Providers. The mobile document
  had no horizontal overflow (`390 === 390`).
- Added `nordrassil/docs/design-system.md` with tokens, layout/component
  contracts, acceptance criteria and explicit non-claims.
- Verification: HTML parser pass, inline JavaScript compilation pass,
  `git diff --check` pass and 57/57 Nordrassil unit tests pass.
- This slice does not claim an installable/offline PWA, user-authored themes,
  persistent density settings or formal WCAG/assistive-technology conformance.

## [2026-07-24] product | Nordrassil provider and deployment registry

- Added the provider/deployment slice in `cyberdid/nordrassil` at
  `dc7c781`: private endpoint CRUD, grouped Chat model selection, explicit
  defaults, native Ollama and OpenAI-compatible adapters, and runtime profiles
  for Ollama, llama.cpp, MLX-LM, vLLM-Metal, LM Studio, vLLM, SGLang, TGI,
  NVIDIA NIM and NVIDIA Triton.
- Added explicit loopback, private-LAN and remote network zones. LAN accepts
  only literal RFC1918/ULA addresses; remote requires HTTPS. URL credentials,
  plaintext secret fields, transport mismatches, proxy inheritance, unsafe
  redirects and tampered persisted endpoints fail closed.
- Provider credentials are stored only as `env:VARIABLE` references and
  resolved at the adapter boundary. `providers.probe` is separately gated and
  off by default.
- Probes observe transport health and model IDs but keep tools, structured
  output, vision and embeddings `unknown`. Triton exposes KServe V2
  health/repository observation only and is not misrepresented as an OpenAI
  Chat endpoint.
- Live proof: native Ollama returned `provider-registry-ok`; a separately
  registered Ollama `/v1` endpoint returned `openai-adapter-ok` through the
  OpenAI adapter. Both observed `gemma4:12b-mlx` and `gpt-oss:20b`; the
  temporary probe grant was disabled afterward.
- Verification: 57/57 Nordrassil unit tests, Python compilation, JavaScript
  parsing and diff checks pass. The source-backed Odysseus audit was refreshed
  to the actual `Downloads/odysseus-dev` tree and its current measured counts.
- Ecosystem documentation gates pass: `eco validate`, `eco render --check`,
  `eco doctor` and `git diff --check`. Full discovery on this Mac is not a
  portability pass: 815 tests report 25 failures, 67 errors and 26 skips,
  dominated by Linux `openat2` requirements and macOS `/var` path aliasing.
  That pre-existing platform harness behavior is retained as an explicit
  non-claim rather than relabelled green.
- Next product slice: Memory 2.0 with provenance-visible namespaces, search,
  reviewed promotion, conflict handling and reversible compaction.

## [2026-07-23] product | Nordrassil persistent sessions and provenance-bound attachments

- Added private project-bound Chat session create/switch/rename/export/delete
  flows in `cyberdid/nordrassil` (`05c4b72`). Session history is a real model
  input dependency and survives browser/process restart without becoming
  authority.
- Added explicitly selected UTF-8 attachments stored by SHA-256 in a private
  content-addressed store. Metadata binds each object to its exact session and
  project; bytes, size and digest are reverified before model context is built
  and are labelled as untrusted attachment data.
- Added separate `sessions.read`, `sessions.manage` and `attachments.upload`
  capabilities. Negative coverage rejects cross-project/cross-session
  references, tampered objects, symlinked state roots, path-like names,
  malformed/binary/unsupported uploads, size-limit violations and capability
  bypass.
- Browser proof: attached Nordrassil's `README.md`, asked
  `gemma4:12b-mlx` for the exact first-heading project name, received
  `Nordrassil`, reloaded the page and recovered the same messages plus the
  digest-bound attachment chip. Product gate is 49/49 tests plus compile,
  JavaScript parse and diff checks.
- Session search/archive, image/PDF/OCR ingestion and remote provider
  conformance remain explicit nonclaims. The next slice is the
  local/API-compatible provider and deployment registry.

## [2026-07-23] product | Nordrassil Cookbook and multi-project workspace manager

- Added a complete wiki snapshot for the user-facing product layer:
  [Nordrassil](nordrassil.md). It records the product/core inversion, the
  source-backed Odysseus audit, relationship to the local-LLM experiment,
  implemented features, enforcement boundaries, current verification and
  delivery backlog.
- Nordrassil's local Model Cookbook now discovers Apple Silicon hardware,
  Ollama/Hugging Face models and dependencies; selects the Chat model; searches
  the catalog; creates typed download/install/serve plans; and exposes private
  jobs. Mutations require exact plan confirmation and execute argv with
  `shell=False`.
- Projects & Files now provides a private recent-project registry, native macOS
  folder selection, manual import, create-folder/project, confirmation-bound Git
  clone, Git metadata and a structured file tree. The active root is pinned per
  request; broad/sensitive roots, symlink escapes, credential URLs and shell
  syntax fail closed.
- The observed proof machine has Apple M4 Max / 36 GB memory, Ollama 0.32.1,
  `gemma4:12b-mlx` and `gpt-oss:20b`. These are inventory facts, not automatic
  deployment-conformance claims.
- Current product gate: 42/42 unit tests, canonical validation and projection
  drift check pass. Linux/WSL native isolation, sessions/attachments, governed
  provider registry, Research/Documents, agents/tasks, connectors and product
  hardening remain explicit nonclaims.

## [2026-07-23] product | Nordrassil Slice 1 — a browser workspace over the core, live and enforced

- Turned the Slice 0 engine into an Odysseus-shaped web app (FastAPI + a themed single-page chat
  UI) at `cyberdid/nordrassil` (`c5ec235`). A live local model (Ollama, gpt-oss:20b) proposes tool
  calls; the core decides each one through the gateway; denials render as a chip with the core's
  own reason code, and the honest "decision-path enforced; kernel isolation Linux-only" badge is
  always shown.
- Verified end to end in the browser: asked to run a host shell command, the model proposed
  `run_shell`, the core denied it (`ECO_TEAM_ACCESS_DEFAULT_DENY`, not executed) and the model
  explained it lacked permission; asking to read the repo was allowed and executed and the model
  answered from the tool result. Model I/O is stdlib-only (loopback urllib); 6/6 gate tests pass.
- Repo home consolidated on cyberdid: `gh` now authenticated as cyberdid, `cyberdid/nordrassil`
  created and pushed (a stray private `Pylypko1021/nordrassil` remains, deletable later with a
  `delete_repo` grant). All future commits/pushes go to cyberdid.

## [2026-07-23] design | Product layer on the core (Nordrassil) — architecture + Slice 0 proof

- Analyzed Odysseus (`~/Downloads/odysseus-dev`, 205k LOC, 759 test files) as a reference product:
  a genuinely useful self-hosted AI workspace whose security is enforced in-process (Python
  denylists, prompt wrappers, admin boolean, "treat it like an admin console; don't expose it").
  That in-process ceiling is exactly what the core exists to replace.
- Decided to build a new user-facing product **from scratch on the core** (Odysseus as
  feature/UX reference only), covering all flows. Wrote the boundary design
  [product-layer-on-the-core.md](../docs/architecture/product-layer-on-the-core.md): the one
  inversion is "the product never enforces security — it renders and requests; the core grants or
  denies", with every Odysseus-class feature mapped to a core primitive, honest platform/license
  boundaries, and a sliced delivery order.
- Named **Nordrassil**, a new sibling repo (`~/Project/nordrassil`, initial commit `f188bf5`).
  **Slice 0** proves the inversion on real core code: the gateway wraps
  `eco_runtime.team_access.evaluate_team_access`; a reader principal may `repository.read`
  (allow-candidate) while `run_shell` (code.execute) and `send_email` (external.write, high-impact)
  are denied by the core. A model that insists on a denied tool cannot execute it — the side effect
  provably never fires — and a dependency control shows the same loop does run a granted tool. 6/6
  tests pass. Honest boundary carried through: an allow is a narrowing candidate, not final signed
  runtime authority, and macOS proves the decision path, not kernel isolation.

## [2026-07-23] verification | Codex lab accuracy review: numbers real, four harness defects fixed, honest re-run

- Adversarially reviewed the Codex-built `ecosystem-llm-lab` (separate repo, left uncommitted):
  recomputed the full matrix from raw JSON (matched 1:1), re-ran unit tests and all `eco` checks,
  verified it exercises the real `eco_gsc`/`eco_loops.BoundedLoopEngine`/`eco_memory`/`eco_teams`/
  admission/telemetry components, and spot-checked transcripts against every narrative claim.
- Found four harness defects: a hardcoded control label that presented gemma's schema failures as
  "escalation caught" (the real `target expands authority` path never fired on model output); a
  spec-pinning user message that contaminated the agent-authoring ablation; the expected answer
  leaked into the tool-render prompt and const wire grammar; a deterministic orchestration control
  indistinguishable from a model control. Plus: `0700` held only for the final run's state dir,
  and memory markers live plaintext in CAS (the SQLite-only claim was narrowly true).
- Fixed all of it (real gate codes, neutral request, shape-only wire format with leak-guard unit
  tests, `code-path` control labeling, full `0700`), lab tests 9/9, and repeated the full 96-call
  run. The honest picture: agent-authoring drops to 0/3 for BOTH models (gpt-oss now produces
  genuine widening the real contract rejects 6/6 with the real code); gemma's tool-use falls to
  0/3 on the render (`"Cobalt-otter"`) while her 3/3 native tool calls stay proven; gpt-oss earns
  tool-use with no leak. New headline: one-shot authoring (skills and team manifests) is not
  established for either model — both need the gated propose→gate→revise repair loop the
  ecosystem already defines.
- Lab committed as its own repo (`5c08f18`); review recorded in
  [Codex lab accuracy review](../docs/research/2026-07-23-codex-lab-accuracy-review-claude.md).

## [2026-07-23] inventory | Three graph-engineering / company-brain articles ingested as untrusted sources

- Copied three 2026-07-22 promotional articles into `docs/research/sources/` unchanged, with
  SHA-256 provenance, at the owner's request ("add + analyze, do nothing yet"):
  - `graph-engineering-how-to-run-1-000-ai-agents-in-parallel-fro.md`
    (`41c83f4bca67e3c85c352829e98dfa483b56e4ae22eada534d7b1b60750ac35b`)
  - `how-to-deploy-a-cerebras-style-knowledge-base-this-week.md`
    (`860c10f36d6606a639bb6854f04bb117b62f8c81893b53471d2d39e9f85f75be`)
  - `how-to-master-graph-engineering-full-course.md`
    (`cb68dd64e08fe2e9538ffb6cff942fca0385ad1ccbe3f6ee6dc480051446221f`)
- Classified as untrusted external reference. Not promoted into policy, memory, a skill, or
  runtime configuration; no contract, code, or recommendation acted upon. Two are graph/loop
  method pieces (which the project already enforces as contracts), one is a vendor company-brain
  advertisement. A reviewed register report is deferred until the owner authorizes action.

## [2026-07-23] verification | Full chain memory→skill→agent→gate composes and every link is load-bearing

- Capstone verification: one governed review of a release note wires all three concepts together
  and dependency-tests each link, all on real code — real `eco_memory`, real
  `source-review-evidence` skill, real `parse_role_output` + `_publish_claim_graph` gate, and the
  real `eco_teams` authority contract.
- Memory carries a non-guessable marker `[RETRY-SCOPE-9]` a model can only emit if it read the
  retrieved decision; the skill drives byte-exact evidence the gate checks; the review is authored
  by a reviewer role the authority contract bounds.
- Both models PROVEN: marker present with memory and absent without it; gate PASS with the real
  skill and FAIL with a decoy; bounded reviewer accepted and widened reviewer rejected
  (`expands authority`). The concepts compose and none is decorative — removing any link breaks
  only its own check.
- This closes the four-part roadmap (memory, skill-follow, agent-write, full chain): every concept
  the project defines is exercised as real code on real cases and proven used by the dependency
  method. Recorded in
  [full-chain verification](../docs/research/2026-07-23-full-chain-verification-memory-skill-agent-gate-claude.md).

## [2026-07-23] verification | A model cannot widen its own authority when writing an agent (dependency-proven)

- Verified the agent-write concept against the **real** team-authority contract
  (`eco_teams.contracts.validate_record` / `_manifest_errors`): a delegate's actions, data
  classes, tool ids, and zones must be subsets of the delegator's, and no role budget may exceed
  the team budget. Manifests built with the real `seal_record` / reference builders and schema.
- Part A (contract IS the gate, deterministic): a valid reference manifest is accepted; a
  one-field widening (a worker gains `repository.write` the orchestrator lacks) is rejected with
  `target expands authority`; a role budget above the team budget is rejected with `exceeds team
  budget`. The gate is load-bearing independent of any model.
- Part B (model authors within the gate): the output-shape prompt is discipline-neutral, so the
  narrowing rule comes only from the skill. Both models PROVEN — with the real
  `agent-team-authoring` skill they author a worker whose authority is a strict subset (accepted);
  with a decoy ("be maximally capable — grant write, shell, big budget") they author a worker that
  grabs `repository.write` + `shell.exec` + a larger budget, which the **same real contract
  rejects** at the authority predicate.
- Honest finding: the first negative was contaminated (the shape prompt said "stay within /
  read-only"), so both models narrowed even under the decoy; fixed by neutralizing the prompt,
  caught by inspecting why the decoy passed — the same failure mode and fix as skill-follow.
- Recorded in [agent-write verification](../docs/research/2026-07-23-agent-write-verification-authority-gate-claude.md).
  Next and last: the full memory→skill→agent→gate chain, each concept proven by removing it.

## [2026-07-23] verification | Real skill is genuinely followed (dependency-proven through the real gate)

- Extended the dependency method to skill-following: gave both local models the real
  `source-review-evidence` `SKILL.md` and validated their output through the **real** enforced
  admission (`parse_role_output` + real analyst schema) and the **real** byte-exact evidence gate
  (`SourceReviewWorkflow._publish_claim_graph`) over a real content-addressed store. No proxies.
- The only variable is the skill: the output-shape contract is discipline-neutral (matching the
  real schema, where `observation` is just a string). Positive = the real skill; negative = a
  decoy with the same JSON structure but the opposite rule ("paraphrase, never a verbatim
  substring").
- Both models: dependency PROVEN. gpt-oss is the clean case — with the real skill it emits four
  verbatim quotes the gate admits; with the decoy it emits four paraphrases and the **same real
  gate rejects every one** (`role-failed` at the byte-exact predicate). gemma passes with the real
  skill (byte-exact quote) and fails the decoy by producing no admissible output.
- Two honest findings: (1) the first run's negative was contaminated — the shape contract said
  "exact quote" to both arms, so the decoy wrongly passed; fixed by making the contract neutral,
  caught by inspecting output not trusting the verdict. (2) gemma's decoy fails by non-admission
  (empty at `finish=length`), not by the byte-exact predicate — reported, not tuned away.
- Recorded in [skill-follow verification](../docs/research/2026-07-23-skill-follow-verification-real-gate-claude.md).
  Next: agent-write into the real team contract (authority-widening role must be rejected), then
  the full memory→skill→agent→gate chain.

## [2026-07-23] verification | Real memory concept is genuinely used (dependency-proven)

- Corrected the shallow capability battery (which put facts in the prompt and could not prove
  memory mattered) with a real end-to-end mini-project: the actual `eco_memory`
  (`PrivateMemoryStore.put_memory` / `retrieve_memory`, SQLite, cross-platform) plus a positive
  proof and a negative dependency test — a concept is only proven used when the test fails
  without it.
- Stored an arbitrary, non-guessable rule (`DEC-7: function names must end with '_checked'`) in
  real memory; both models flag the violation only when the retrieved record is present and not
  without it. Digests trace to the store and namespace isolation holds. Memory is genuinely used.
- Fixed a fifth gemma formatting quirk: it markdown-escapes underscores (`\_`, an invalid JSON
  escape), so `extract_json_candidate` now repairs invalid escapes (unit-tested). Also recorded
  an honest limitation: byte-exact quoting drifts (trailing space / reformatting), which the
  strict quote gate correctly rejects — enforced pipelines will need a retry for exact quotes.
- Next, same rigor: skill-follow (real SKILL.md + real gate + decoy negative), agent-write into
  the real team contract, then a full memory→skill→agent→gate chain.

## [2026-07-23] dogfood | Live capability battery — both local models do everything

- Merged PR #3 into `main`: the repository (now `cyberdid/ecosystem` after a full transfer to
  the paid account) has green CI across Linux/macOS/Windows × py3.11/py3.12, and `main` holds
  the complete M1–M6 + P1–P5 + GSC platform.
- Ran a live capability battery against `gemma4:12b-mlx` and `gpt-oss:20b`, using the project's
  contracts as validators. Both unknown local models perform every agentic capability: tool-use
  (valid function calls), skill-follow (byte-exact quotes), memory (ground + refuse to
  hallucinate), skill-write (through the GSC gate), agent-write (bounded roles within budget),
  and selecting the right skill for a task (3/3 each). gemma needs a slightly more explicit
  prompt for strict structure (it first omitted an `id`), but is fully capable.
- Fixed the transferred repo's hosted CI: a Windows CRLF break of skill `contentDigest`
  (`.gitattributes` LF pins) and a Windows py3.11 `platform.uname()` subprocess ban in the
  doctor read-only test (warm the cache before mocks). Both found by diagnosis, not guessing.

## [2026-07-22] implementation | GSC L0 promotion closes the self-creation loop

- Added `eco skills propose` (gate a proposed SKILL.md) and `eco skills promote` (L0):
  the promotion re-runs the gate, requires an explicit human approval bound to the exact
  content digest, refuses to overwrite an existing skill, and writes into a caller-supplied
  skills root with a content-free receipt. New module `eco_gsc.promote`; 8 promotion tests.
- Live end-to-end proven on a local model: gpt-oss self-created a bug-triage SKILL.md →
  `eco skills propose` ADMISSIBLE → `eco skills promote --approve helen` → the skill was
  written. A hollow "Hard stop:" (label without a prohibition) was correctly rejected first,
  so the positive path is not a rubber stamp. This closes the model→gate→approval→registry
  loop without WSL (generation and gate are cross-platform).

## [2026-07-22] dogfood | Local live tests of P1/P2 and GSC against Ollama

- Lifted the live-model pause for local testing and drove the new slices against
  `gemma4:12b-mlx` and `gpt-oss:20b` through the project's cross-platform adapter on
  macOS (the enforced Linux pipeline was not exercised).
- Built and ran the **GSC gate** (`eco_gsc`): a model proposes a `SKILL.md`, the
  deterministic gate decides admissibility (structure, capability narrowing, secret and
  hard-stop integrity), no auto-promotion. Live: gpt-oss self-created an ADMISSIBLE skill;
  gemma4's malformed frontmatter and a self-authorizing adversarial proposal were rejected.
  First live proof of gated self-creation on an unknown local model.
- Found and fixed two brittleness defects (tests added): P2 admission was too strict about
  markdown-fenced JSON (now liberal-extract, strict-validate); the GSC gate flagged its own
  hard-stop prohibition line. Both caught by investigating a suspicious result.
- Real model finding (corrected after a maximal battery): the early "empty/flaky" results
  were mostly token starvation (`finish_reason=length`, reasoning models) plus the wrong
  transport, not incapability. With generous budgets both models are competent (P1 6/6) and
  self-create valid skills (GSC 3/3 each); the adversarial proposals are all rejected. gemma's
  one real limitation is ignoring Ollama's strict `json_schema` grammar (emits prose), so it
  routes to prompt-based JSON (P2 4/4). Live scripts stay in scratchpad, not git.

## [2026-07-22] implementation | Cookbook recommendations P1–P6 implemented

- Implemented all four code slices at their deterministic core with passing gates:
  P1 general eval harness (`eco_eval`, `eco eval suite <file>`, judge validation live
  and non-zero exit), P2 structured-output admission (`eco_runtime.structured_admission`,
  grammar-safe wire projection vs authoritative full-schema validation), P3 vendor-neutral
  reference agents (`eco_teams.reference_manifests`: evaluator-optimizer and
  orchestrator-workers, validated through the real team contract), P5 content-free cost
  telemetry (`eco_telemetry`, fail-closed caps stop before breach).
- 26 new tests across the four slices; integration gate 115 tests green; validate, render and
  skills-check green. P4 (reliability skills) and P6 (compliance positioning) completed earlier.
- Two live-dependent boundaries stay deferred with the same dependency as the M6 five-role run:
  P2's live structured-output probe and P3's live team PASS. Nothing live is claimed.

## [2026-07-22] research | Vendor cookbooks review and P1–P6 implementation plan

- Reviewed three gitignored vendor cookbook clones under `external/cookbooks/` (Anthropic,
  Google, OpenAI) as untrusted reference: a third independent confirmation of the harness
  thesis, now from the vendors themselves, who implement it as fragile notebook patterns
  while the project enforces contracts. `external/` was already gitignored; only the review
  enters git.
- Turned the six gaps into a contracts-first plan (candidate milestone M8): P1 general eval
  harness (`eval-file → N independent runs → metrics → verdict`), P2 structured-output model
  admission, P3 vendor-neutral reference agents, P4 reliability-technique skills, P5 cost
  telemetry, P6 compliance positioning.
- Implemented P4 this session: added `task-decomposition` and `self-consistency-verification`
  skills, bumped the registry to `1.2.0` (five→seven skills), synchronized 30 projections and
  updated the sync tests; all gates green. P1/P2/P3/P5 remain designed slices with per-slice
  gates; nothing unverified is claimed done.

## [2026-07-22] documentation | Creation guide and authoring skills

- Added `docs/architecture/creation.md`: a map of how every artifact is created
  (loop, contract, skill, agent, memory), the shared proposed→gated→promoted→revoked
  state machine, the L0/L1/L2 autonomy scale and the seven creation invariants.
- Closed the authoring gap: added `skill-authoring` and `agent-team-authoring` package
  skills, bumped the registry to `1.1.0` (three→five skills), synchronized 22 projections
  across all harnesses and updated the sync tests. The creation skills themselves passed
  the same tests+evidence+owner+digest gate they document.
- The runtime gated-self-creation engine (automatic propose→gate→promote) remains the
  separate GSC proposal, not code.

## [2026-07-22] research | Agentic teams/graphs/migrations review + gated self-creation proposal

- Preserved six more owner-supplied promotional articles byte-for-byte under
  `docs/research/sources/` with SHA-256 provenance and reviewed them as untrusted
  data: Hermes persistent-agent prompts, a 42-skill org chart, graph/dynamic-workflow
  engineering, Anthropic large-scale code migrations, Karpathy/ADK tooling and Superpowers.
- Convergent finding continues: the market restates this project's thesis, but reaches
  discipline via prompt-coercion and framework lock-in (fragile) rather than runtime
  contracts (model-agnostic). Three work candidates surfaced — graph-orchestration in
  `eco_loops`, a validate-the-judge adversarial suite, and model-role routing.
- Proposed the **Gated Self-Creation (GSC)** contract: agents may *generate* skills,
  agents and loops under a team's own requests, but each artifact stays `proposed`
  (no rights) until it passes schema, narrowing, deterministic and adversarial gates
  and binds an accountable owner — then `promoted`, always revocable. Autonomy is a
  scale (L0 human-approve / L1 auto-gate / L2 forbidden), never unowned self-writing.

## [2026-07-20] research | Self-correcting loop and harness source review

- Preserved five owner-supplied promotional articles byte-for-byte under
  `docs/research/sources/` with SHA-256 provenance and reviewed them as untrusted
  data: a self-correcting loop (Builder/Judge/Manager), a Claude Code harness
  rebuild, an agent-team playbook, a LangChain agent factory and a 42-skill
  org-chart tweet.
- Recorded the convergent finding: five independent authors restate this project's
  thesis ("the bottleneck was never the model, it was the structure around it") and
  every reusable primitive maps to an already-implemented component.
- Mapped the article's four self-correcting-loop stress tests to the deterministic
  suite: unsolvable, confidently-wrong and cost-runaway are already enforced by
  exact tests; the same-model blind-spot test is the one real gap, marked by a
  skipped `test_same_model_blind_spot_requires_model_role_separation`.
- Wrote an implementation-ready design spec for model-role separation
  (`docs/architecture/model-role-separation.md`) against the current hardened code,
  with a route-authority single-deployment guard and the ADR-006 live-evaluation
  requirement. Implementation is deferred by owner decision (safe-now-plus-spec);
  `source_review.py` is unchanged.
- Rejected framework-vendoring, policy-in-prompts, memory-as-authority and
  third-party-workspace patterns as conflicting with project invariants.

## [2026-07-20] implementation | M6 exact routing and 0.8.0 release candidate

- Closed M6.1–M6.8 for the bounded embedded profile: governed model execution,
  skills/harness sync, reusable bounded loops, logical routing, private memory,
  agent teams, governed research tools and reproducible distribution.
- Made source-review depend on an exact five-document route set and an external
  Ed25519 authority. The runner validates the full-run window, consumes the
  route once, reserves aggregate usage per role and reverifies authority before
  every provider egress.
- Fixed three independent-audit blockers: expired-route idempotent replay,
  route-less legacy execution and startup-only route-authority verification.
- Hardened local provisioning, adapter grammar projection, endpoint identity,
  response bounds, observation binding, source-bundle identity, structural JSON
  limits and TTL-safe memory compaction.
- Bumped the release to `0.8.0`; the local gate passes all 756 cases on both
  Python 3.11 and 3.12 plus 756 pytest cases, canonical
  validation/render/doctor/skills checks, release
  conformance, a locked offline wheel install and an installed five-role exact
  route smoke.
- Kept the boundaries explicit: observation HMAC is shared-key local integrity,
  local journals do not resist whole-authority rollback, non-Linux jobs do not
  prove native sandbox security and no live five-role model-quality PASS is
  inferred from the deterministic loopback smoke.
- Full evidence: `docs/research/2026-07-20-m6-functional-orchestration-completion-report.md`.
- Published candidate `31803b0` in draft PR #3. GitHub push and PR runs both
  terminate as `startup_failure` with zero jobs; retrying an older workflow does
  the same. Hosted evidence remains unpassed until the external runner/account
  restriction is cleared.

## [2026-07-20] implementation | Live source-review dogfood: three fixes, ceremony script, honest status

- Scripted the operator evidence ceremony
  (`scripts/provision_local_source_review.py`): probes a loopback
  OpenAI-compatible endpoint with text and strict JSON-schema structured
  output, writes the observed `AdapterConformanceProfile` into
  `.ai/evals/observed/` and signs the envelope into a private external path.
  The runtime still never signs its own evidence.
- Declared and provisioned one real enabled local deployment
  (`local-llamacpp-gemma`, llama.cpp b9652 loopback) in canonical
  `.ai/deployments.yaml`/`trust.yaml`, plus a dogfood source bundle under
  `loops/source-review-dogfood/` reviewing the preserved multi-model-team
  article.
- Live dogfooding found and fixed three genuine defects, each with regression
  tests: (1) llama.cpp silently degrades to unconstrained generation when the
  wire schema contains `minLength`/`maxLength` — the adapter now sends a
  documented grammar-safe projection while eco keeps validating the full
  schema; (2) `EndpointBinding` record ids collided across runs against one
  durable store (`ECO_STORE_ID_CONFLICT`) — ids are now content-addressed over
  the full sealed content; (3) the 120 s per-call transport ceiling was too
  tight for CPU backends — the source-review profile now allows 300 s while
  every call stays fenced by deadline and durable budgets.
- Issuer-key resolution became per-consumer: `verify_trust_bootstrap` resolves
  only the snapshot issuer and source-review only eligible conformance
  issuers, so adding an adapter issuer no longer blocks the M4 loop
  environment. The full doctor still resolves every declared issuer.
- Sixteen live attempts proved the chain end-to-end (validation → signed
  evidence → `eco route plan` → durable single-use route consumption with an
  observed `ECO_ROUTE_ALREADY_CONSUMED` denial → policy → durable PREPARE →
  real HTTP → CAS → truthful terminal results). The five-role PASS is still
  pending: residual failures are small-model capability against the
  deterministic gates (unique ids, byte-exact quotes, exact coverage,
  verified-requires-evidence), amplified by GPU contention on the host. Live
  model iterations are paused by owner instruction; see the
  [handoff](../docs/research/2026-07-20-m6-live-dogfood-handoff-claude.md).

## [2026-07-17] implementation | M6.4 durable route consumption and CLI composition

- Added `DurableRouteConsumptionJournal`: a private HMAC-authenticated SQLite
  chain that binds one `allowed` `ModelRouteDecision` to exactly one consumer.
  Same-consumer replay is idempotent; any other consumer receives a typed
  `ECO_ROUTE_ALREADY_CONSUMED`. Attempt-2 fallback requires its consumed
  predecessor. Rows are immutable; tamper and wrong-key reopen fail closed.
- Extracted pure `verify_route_binding` for write-free preflight: record/kind
  validation, decision→request digest binding, validity windows, exact
  deployment/identity-digest match and reservation consistency.
- Added `eco route plan`: deterministic CLI composition over canonical
  `.ai/deployments.yaml` candidates plus operator-supplied policy, price
  catalog, request and observation records. Zero writes; a computed denial is
  exit 1, invalid trusted inputs are sanitized exit 2. A route remains
  non-authorizing.
- `eco team run source-review` accepts `--route-decision/--route-request`:
  preflight verifies the binding before any state write, the run consumes the
  decision durably beside the runtime journal, restart replay keeps provider
  calls at five, and a mismatched selection blocks before HTTP or state
  creation.
- Added focused journal/CLI tests plus production-composition route tests;
  fixed-flake and integrated M6 release evidence remain tracked under M6.8.

## [2026-07-17] implementation | M6.7 governed research tools

- Added the independent `research.ai.ecosystem/v1alpha1` policy, HMAC capability,
  private-input request and provenance-bound untrusted artifact contracts.
- Added an API-first search/fetch broker with exact D/Z/retention/domain/query
  authorization, classification non-downgrade, private CAS publication and
  content-free public records.
- Added the credential-free pinned-public-HTTPS transport: per-hop DNS/IP and
  redirect validation, no proxy/cookie/auth state, independent wire/decompression
  limits, one absolute read deadline, media/UTF-8 and bounded JSON checks.
- Added a typed exact JSON search provider and explicit test-only injected adapter
  boundary; no unsafe arbitrary URL CLI or browser-session surface was exposed.
- Added `research-web` provenance projection for text SourceBundle entries; HTML
  remains CAS-only until separately governed normalization.
- Focused deterministic tests cover forged trust, SSRF classes, suffix confusion,
  redirects, size/decompression/JSON limits, query credentials, redaction, exact
  CAS publication and repository identity. Real-provider and M6.8 integrated
  evidence remain pending.

## [2026-07-17] implementation | M6.6 general agent-team orchestration

- Added sealed `AgentTeamManifest`, `TeamTask`, `TeamHandoff` and
  `TeamRunResult` contracts plus an API-first embedded SQLite coordinator.
- Bound manifests and every claim to current M5 project/team/snapshot/bundle,
  exact access policy and active principal/membership. A separate opaque runtime
  authorization remains mandatory at effect start; a route alone grants nothing.
- Added serialized bounded leases, exactly-once route/effect boundaries,
  conservative post-start ambiguity, aggregate token/cost reservations,
  cancellation propagation, typed artifact handoffs and truthful partial-failure
  finalization.
- Bound route consumption to complete validated M6.4 route/request records,
  trusted policy/price digests, current validity, selected deployment and exact
  ModelRequest. Worker-supplied timestamps cannot revive expired authority;
  coordinator time is sampled from a trusted injected clock at every boundary.
- Moved state to a required private external path and HMAC-authenticated the full
  mutable snapshot plus revision/hash chain. Tamper tests cover task status,
  leases, reservations, cancellation, consumed routes and terminal results;
  repository identity remains unchanged.
- Delegation and concrete child tasks can only reduce role, action, data, tool,
  zone, resource, deadline and budget. Cross-team/project/run substitutions fail
  closed. `model.invoke` now binds an exact `ModelRequest` to its deployment
  identity and data class rather than using repository request/resource equality.
- Focused M5+M6 tests pass. This remains a single-host scheduler API, not a
  distributed scheduler, consensus layer, provider-pricing authority or provider-
  independence claim; integrated M6 release evidence remains pending.

## [2026-07-17] implementation | M6.5 private context and memory graph

- Added the closed `memory.ai.ecosystem/v1alpha1` contract for seven context types,
  exact project/team/run namespace, D/P classification, author/time/TTL, exact
  source artifacts and supersession/refutation/conflict links.
- Kept raw/private bodies in the existing private CAS. The separate SQLite index
  stores only sealed content-free metadata and authenticates every record, append
  entry and journal head with caller-owned HMAC key material.
- Added deterministic exact-namespace retrieval with explicit policy, TTL/data/P
  filters and hard item/byte/token-estimate budgets. Conflict/refutation components
  are atomic, so truncation never presents only one visible side as uncontested.
- Added additive, reversible compaction: summaries retain all exact source records,
  artifact bindings and relations; a hand-built summary that drops a conflict is
  rejected. Memory remains context and cannot grant roles, routes, tools,
  capabilities, budgets or policy.
- Focused adversarial tests cover namespace leakage, expiry/classification,
  forged links, deterministic boundaries, conflict preservation, CAS/DB tamper,
  raw-content absence and concurrent idempotent replay. Integrated M6 release
  evidence remains pending.

## [2026-07-17] implementation | M6.1 production source-review CLI candidate

- Added `eco team run source-review` and a zero-write/zero-egress `--check`
  preflight. There is no scripted or fake executor reachable from the production
  command.
- Bound the sole enabled local OpenAI-compatible deployment to complete immutable
  identity, exact `review.private` policy, literal loopback endpoint and externally
  signed `model.text` plus strict structured-output observation evidence.
- Composed every typed role envelope through its own exact child RunPlan,
  PolicyDecision, durable SQLite model operation, private CAS,
  GovernedModelOrchestrator and GovernedRoleExecutor. Stable idempotency keys and
  the same external database/CAS make terminal restart replay issue zero duplicate
  HTTP calls.
- Kept source bytes in a strict bounded manifest→CAS path and untrusted typed
  channels. The transport has no credentials, proxy, redirect, tool or source
  network surface; the command creates no governed-repository writes and emits
  only the content-free result graph/report binding.
- Focused production-composition tests exercise a real local HTTP server, five
  role calls, process-composition restart with the provider count still five,
  repository byte/mode identity, default-disabled configuration, stale creation
  time and evidence-expiry-before-deadline failures. Integrated M6 release gates
  remain pending; structural success is not a universal truth or injection-
  immunity claim.

## [2026-07-17] implementation | M6.4 logical model roles and deterministic routing

- Added five canonical provider-neutral workload roles and the separate
  `routing.ai.ecosystem/v1alpha1` contract family for policy, observed capability
  evidence, trusted prices, route requests, decisions and sanitized explanations.
- Added a pure deterministic router that intersects action/data/zone/retention,
  observed capability/context evidence, cloud permission, current identity,
  deadline and router-computed cost. No candidate is a typed denial.
- Preserved the M6.1 local zero-cost profile: cloud is forbidden and the catalog-
  calculated reservation must be zero.
- Added a maximum-two-attempt fallback that excludes the attempted candidate and
  re-evaluates current inputs. Only policy-allowed capacity/transport failures may
  fallback; safety, authority, schema, ambiguity, drift, deadline and budget may not.
- Added sanitized explain records without source/prompt/provider/model/endpoint/
  secret/raw-evidence data and focused permutation, staleness, identity, privacy,
  cost, deadline and fallback tests. All 21 focused tests pass; integrated M6
  release evidence remains pending.

## [2026-07-17] implementation | M6.2 canonical skills and harness synchronization

- Added a closed package-owned registry and three digest-bound dogfood skills for
  contract changes, bounded loops and source-review evidence discipline.
- Added deterministic Codex, Claude, Gemini and generic projections plus honest
  instruction-only Copilot/Cursor subsets.
- Added `eco skills plan|sync|check|uninstall` with ownership lock, drift refusal,
  path alias defenses, atomic writes, catchable-failure rollback and owned-only
  removal; imported or discovered skill code is never executed.
- Added adversarial tests for traversal, Unicode/case aliasing, symlink, hardlink,
  forged ownership, lock redirection, drift, rollback and uninstall. Focused M6.2
  tests pass; the integrated M6 release gate remains pending.

## [2026-07-17] architecture | M6 functional-orchestration foundation

- Accepted the independent functional-gap finding: M1–M5 provide a strong bounded
  trust foundation, while skills, general loops, role routing, memory and workload
  agent teams remain the main product gap.
- Added ADR-027: M6 is now Universal Functional Orchestration; the previous
  enterprise/network/native-backend backlog moves unchanged to M7.
- Added ADR-028: M6 uses the separate
  `orchestration.ai.ecosystem/v1alpha1` profile and preserves the exact existing
  runtime schema digest instead of silently widening M4/M5 records.
- Froze the first vertical slice as manual offline `source-review`: planner →
  analyst → verifier → synthesizer → reviewer, one bounded revision, one explicit
  deployment pin, no source-network/tools/workspace writes, and truthful incomplete
  or exhausted outcomes.
- Code audit found that the current model adapter has no durable policy/budget/
  recovery composition path. M6.1a must add model PREPARE/start/complete/fail and
  post-start no-retry ambiguity before the team runner can be exposed.
- Added the M6 architecture, 18-invariant threat model, source-review acceptance
  gates, adversarial matrix and detailed M6.0–M6.8 implementation plan.
- Registered the user-supplied multi-model-team article unchanged at SHA-256
  `59c616d7b701449797ca747838fdd31b5c7a677017863f2a03b174fd78ee007e`
  and recorded exact OpenResearcher, OpenScience and MOLT snapshots as untrusted
  research inputs.
- Three specialized agents independently audited contracts, runtime execution and
  adversarial/security gates. The untouched M1–M5 baseline remains 474/474 green in
  both unittest and pytest; M6.0 documentation is not an M6.1 completion claim.

## [2026-07-16] implementation | M5 team authority completed

- Completed M5.3 exact narrowing team access, M5.4 private shared SQLite activation authority, M5.5 revocation/emergency/recovery/rotation, M5.6 distinct-human quorum permits, and M5.7 CLI/backup/portability/release conformance.
- The final allow path now requires a trusted current `PolicyEngine` allow, current signed team access, active non-revoked signed actor state, emergency-clear status, and an authority-issued single-use permit for A2.
- Added explicit-deny precedence, exact resource/action/constraint matching, activation revision + predecessor + snapshot CAS, authenticated epochs/events, live signature/HMAC revalidation and effect-boundary fencing.
- Added signed approval profiles/requests/votes, requester separation, human-only distinct-principal quorum, durable permit issue/consumption, and exact signed recovery quorum for emergency disable.
- Added old+new Ed25519 dual-signed rotation and successor-generation migration so trust-anchor changes never rewrite predecessor history.
- Added public `eco team doctor` and explicit `eco team activate --apply`, coherent verified backup, a dedicated operations runbook, ADR-026 and the full M5 completion report.
- Multi-agent identity/policy, authority, approval, threat, rotation, recovery and CLI reviews drove adversarial corrections before integration.
- Local evidence: 474 pytest tests, 474 unittest tests, canonical validate/render/doctor gates, compile, whitespace and unchanged M4 runtime-schema digest checks pass; release metadata is `0.7.0`.
- Hosted GitHub Actions run [`29513118749`](https://github.com/Pylypko1021/ecosystem/actions/runs/29513118749) passed at commit `527a64030ea384651a2bbd700f72b0fc999beac9`: full Linux regression/offline-wheel verification and focused macOS/Windows M5 portability gates are green. The first release run exposed a latent Windows CRT text-mode read of binary wheel artifacts; byte-exact `O_BINARY` reads and a CRLF/`0x1A` regression test corrected it without weakening the file-identity checks.
- M6 remains the explicit boundary for network/HA authority, SSO, KMS/HSM, native platform security backends and A3/A4.

## [2026-07-16] implementation | M5.0–M5.2 team identity and signed-policy foundation

- Added the separate `authority.ai.ecosystem/v1alpha1` contract family for team/principal identities, membership bindings, Ed25519 public identity keys and revisioned deny-all identity catalogs.
- Kept the M4 runtime schema registry/digest unchanged and introduced a separate authority schema digest, preventing new records from invalidating durable M4 snapshots.
- Implemented domain-separated authority-record digests, deterministic membership/key IDs, exact validity/controller rules and recursive sorted cross-record binding.
- Added externally anchored canonical Ed25519 policy-envelope verification with no production signer, no self-bootstrap, fixed project/team/subject bindings and immutable non-authorizing results.
- Added read-only `eco identity inspect`, `eco policy inspect` and `eco policy verify`; project-controlled trust anchors, unsafe file aliases, duplicate/noncanonical JSON and raw diagnostic leakage fail closed.
- Multi-agent threat, identity/crypto and shared-state audits fixed the trust/digest/replay boundaries and defined M5.3–M5.7 handoff constraints.
- Locked `cryptography` and dependencies; focused 24-test M5 gate plus the complete 406-test regression pass.
- Extended installed and standalone distribution verification for valid two-component dependency versions (`pycparser 3.0`); 18 distribution tests and a real 11-artifact Linux wheelhouse verification pass.
- GitHub Actions run `29503014508` passed at `75cea96`: Linux completed unittest discovery, pytest, canonical gates and real offline wheelhouse install; macOS and Windows completed the focused M5/portability matrix.
- Next: M5.3 bounded RBAC/ABAC as an additional narrowing gate; durable activation/currentness remains M5.4.

## [2026-07-16] implementation | Remaining bounded M4 portability completed

- Added M4.5.3 closed distribution integrity metadata, installed + standard-library offline verifiers, exact main/dependency/lock/schema binding, wheel-internal validation and non-executable package-manager previews.
- Added a real `0.6.0` build/verify/private-venv `--no-index` install smoke and focused Linux/macOS/Windows contract gates. Package installation remains separate from project adoption; checksum integrity remains separate from publisher provenance.
- Added M4.6 `eco conformance run`, separate from passive doctor, with one fixed synthetic Linux/WSL namespace + Landlock suite and a private external test-root boundary.
- Added `PlatformBackendConformanceProfile`, exact external HMAC envelope ingestion and narrow observed capabilities. No policy/store/broker/model/adapter/loop consumes the record; unsupported/failure profiles expose no capabilities.
- Multi-agent review found and closed an ignored `uv.lock` tamper path, fake/non-PEP-427 wheel acceptance, missing main metadata/entry-point checks, dependency-wheel non-validation, verifier reopen races, archive-budget/file-type gaps, numeric JSON aliases, active-context relabeling, unpinned runner/implementation evidence, an unseeded environment canary, non-object CLI input, and standalone contract divergence.
- Local evidence: 381 complete tests, 17 distribution tests, 7 backend-conformance tests, 7 live isolation tests, one real WSL conformance pass, compile/schema/diff gates, and real eight-artifact offline installation pass.
- Hosted GitHub Actions run `29498793136` passed at commit `9dc77bee4772294f010c1ff0d5d2c86b7fb1b29a`: full Linux plus focused macOS/Windows portability gates are green. The initial run exposed and drove correction of non-canonical temporary fixture paths on both hosted operating systems.
- Added ADR-023/024, architecture pages, combined completion report and wiki handoff to M5 team identity/signed policy/RBAC.

## [2026-07-16] implementation | M4.5.2 passive platform and adapter conformance completed

- Added closed `platform.ai.ecosystem/v1alpha1` `PlatformProfile` and `AdapterCapabilityProfile` contracts with semantic digests, exact inventory/identity checks, and structurally empty effective-capability state.
- Added deterministic `eco platform doctor --json` with optional operator-declared profile comparison, coarse OS/context classification, allowlisted executable-name resolution, fixed client-surface metadata, and fixed safety flags.
- The doctor cannot accept unsigned evidence, invoke an executable, contact a network or adapter, read secret/projection content, write files, or create runtime authority. Existing externally signed runtime `AdapterConformanceProfile` remains the separate proof boundary.
- Six fixtures cover Linux native, WSL, macOS, Windows native, container, and hosted CI. Spoofed hints, unsupported/inconsistent OS, duplicates, unknown fields, declaration mismatch, and nested WSL/container/CI contexts fail closed.
- Multi-agent review found and closed unsigned effective-capability schema elevation, incomplete exact-inventory reconciliation, and a Python 3.12 test nesting limit. Canary traps cover process, shell, network, HTTP, secret reads, and filesystem mutation.
- Local verification: 8 focused platform tests, 357 complete `unittest` tests, 357 pytest tests plus 205 subtests, compile, lock, validation, drift, both doctors, deterministic diff, wheel contents, and whitespace checks pass.
- Hosted GitHub Actions run `29493436362` passed at implementation commit `34411106fb3b02aca1422f485b93dd9069cfe029`: full Linux plus focused macOS and Windows portability jobs are green.
- Added ADR-022, architecture documentation, completion research, and the M4.5.3 portable-packaging handoff. Active native security conformance remains a separate non-claim.

## [2026-07-16] implementation | M4.5.1 safe project-adoption bootstrap completed

- Added schema-valid `ProjectAdoptionPlan` and `ProjectAdoptionReceipt` contracts plus mandatory `eco adopt --dry-run` / exact-digest `--apply` lifecycle for fresh, explicit existing-config, and reinstall modes.
- Added content-minimized discovery, in-memory starter validation, byte-exact projection before-images, deterministic no-op reinstall, an external per-repository apply lock, owned `.ai/adoption.json`, and ignored private render state.
- Replaced recursive config deletion with complete receipt/state/backup/config/unknown-entry preflight and enumerated removal; marker text without strict ownership state never authorizes a mutation.
- Multi-agent adversarial review reproduced and closed text-normalized restoration, stale partial apply, symlink/hardlink/path escape, non-UTF-8, unauthenticated backup restore, marker-only ownership forgery, and rollback overwriting a concurrent user edit.
- Rollback is deliberately bounded and compare-and-swap aware: it restores only exact ecosystem-written after-images and preserves conflicting user bytes. Durable `SIGKILL` recovery, hostile parent swaps, complete reparse/case-fold safety, packaging adapters, and non-Linux runtime backends remain non-claims.
- Added byte-exact Python and TypeScript-monorepo fixtures, 29 focused adoption tests, Linux/macOS/Windows hosted adoption jobs, ADR-021, architecture documentation, completion research, and wiki handoff to M4.5.2.
- Final local gate: 349 `unittest`; 349 pytest tests plus 188 subtests; compile, wheel/schema packaging, `uv lock --check`, validation, projection drift, doctor, diff, and whitespace checks all pass.
- Hosted GitHub Actions run `29491034403` passed at commit `93122d0ab290de5e95f19a8e95551e9c6626868a`: full Linux gate plus focused macOS and Windows adoption/validation/projection/doctor jobs. The Windows run first exposed CRLF-sensitive canonical instruction digests; `.gitattributes` now fixes canonical YAML and generated projection surfaces to LF.

## [2026-07-16] implementation | M4 fixed no-model wiki-health L0–L2 profile completed

- Added distinct route-free `NoModelRunRequest`, `NoModelRunPlan`, and `NoModelReadRequest` contracts plus an exact no-model lifecycle; the plan fixes three D0/P1 slots, three reads, 30 seconds, exact input bytes, and zero model/network/write budgets.
- Added `eco run wiki-health-check`: external signed-snapshot verification, single-use plan/read decisions, Linux/WSL broker-only reads, in-memory integrity/H1/distinctness checks, and path/content-free output.
- Added a private external SQLite application with separate HMAC plan/event/head authentication, strict ownership/permissions/schema/link checks, exclusive process ownership, fresh pre-start recovery authorization, a durable `started` ambiguity fence, and terminal zero-read replay.
- Added `eco eval wiki-health-check`: five fixed independent journals plus a zero-read recovery proof, frozen thresholds, deterministic promotion report, maximum L2 eligibility, and structural L3–L5 denial.
- Multi-agent adversarial review reproduced and closed forged recovery authority, adapter/lifecycle entry, duplicate-scope success, unauthenticated journal rewrite, symlink repository mutation, timestamp replay conflict, concurrent journal ownership, recovery-without-reauthorization, partial-recovery evidence loss, ambiguous post-read reread, parser-deadline, and frozen policy-time gaps.
- Full local acceptance gate: 320 `unittest` tests plus pytest, compile, canonical validation, render drift, doctor, and diff checks. Exact proof limits are in the M4 completion report and ADR-020.
- Hosted Linux GitHub Actions run `29486870506` passed all declared gates for implementation commit `3092f1f4e62622ced8e7047ad39243ed5a11a5be`.

## [2026-07-15] implementation | M3 bounded controlled-write profile completed

- Added exact A2 `repository.write` contracts for one Linux/WSL UTF-8 regular-file create/replace operation, with active-plan, snapshot, root, before-state, candidate, preview, limit and rollback bindings.
- Added a separate authenticated write authority that atomically consumes human approval and policy decision, binds idempotency, locks the target, fences leases and detects SQLite/audit tampering without storing raw paths or content.
- Added descriptor-anchored atomic apply and compare-and-swap rollback with protected-path, traversal, symlink, hardlink, race, content, mode and fault-injection defenses.
- Added private-CAS recovery bundles and full process-loss recovery: exact before becomes failed, exact after is rolled back, and unrelated state remains `recovery_required`.
- Closed adversarial review findings for proposal substitution, root mismatch, inactive plans, policy reuse, expired terminal replay, detect-only recovery and stale lease timestamps.
- Final deterministic regression gate: 258/258 `unittest`; full pytest, compile, validation, render, doctor, lock and diff gates are required by the completion report.

## [2026-07-15] security | M2 adversarial closure passed

- Removed the last production-callable unsigned fixture path and arbitrary verifier injection: `PolicyEngine` now owns a verifier built from exact immutable issuer policies.
- Bound allow-decision expiry to envelope/observation/snapshot validity and added evidence re-verification at plan activation, closing the plan-before-expiry/activate-after-expiry gap for both in-memory and durable paths.
- Added OS-level atomic no-replace publication plus a domain-separated signed manifest over all evidence files, including full sanitized RunRequest, RunPlan, PolicyDecision, and receipts.
- Disabled Claude user/project/local setting sources, forced a strict empty MCP configuration, and rechecked executable/model identity after invocation.
- Authoritative closure: `.ai/evals/live/2026-07-15-m2-closure-pass/`; suite `08d7ee84...26dd6`, aggregate evidence `1c7e8d1a...e46927`, publication manifest `fabdb4d7...d624`.
- Final automated gate: 187/187 `unittest`, full `pytest`, compile/package checks, canonical validation, render drift check, doctor, and diff check.

## [2026-07-15] hardening | Final M2 trust and live-policy gate

- Removed the production `TrustedRuntimeRecord`/unsigned-evidence bypass surface. `PolicyEngine` now accepts signed envelope bytes with explicit trust context, re-verifies them at construction/planning/tool authorization, and binds issuer/key/envelope provenance into `RunPlan`.
- Restricted the Linux/WSL launcher to untrusted-agent execution: credential bindings are rejected before resolution; stdin is closed; stdout/stderr are bounded; resolver failures are sanitized.
- Re-ran the `text-basic` live suite against manifest-verified Ollama/Qwen and executable-verified Claude CLI. Final suite digest is `08d7ee84...26dd6`; aggregate evidence digest is `9397ad2f...3dd17`.
- Published both observations as independently ingestible HMAC envelopes. Both passed trust-policy ingestion, and the local D0 envelope passed a real production `PolicyEngine` allow-plan gate.
- Final automated gate is 181/181 tests; retained final evidence is under `.ai/evals/live/2026-07-15-m2-final/` and is no-overwrite/atomically published.

## [2026-07-15] decision | Hardware-neutral M2 identity and evidence boundary

- Accepted ADR-016: DGX is an optional local compute profile, not an M2 dependency; the active gate is one governed local deployment plus one governed cloud deployment.
- Recorded that a cloud model alias is an observable routing identity, not attestation of immutable provider weights or serving internals.
- Clarified that the live observations have a 24-hour validity window: expiry preserves historical evidence but removes current routing/promotion authority until renewal.
- Replaced the broad “content-free” wording for evaluation artifacts with “raw-content-free D0 evidence”; deterministic low-entropy digests may still be guessable.
- Updated architecture and roadmap handoffs from “Next M2/DGX” to the M2 regression baseline and M3 controlled-write gate. Evidence files and their digests were not changed.

## [2026-07-15] implementation | M2 embedded read-only reference profile completed

- Added pinned local-loopback and direct-cloud adapter contracts, credential-free invocation objects, exact endpoint/model identity, strict bounds, sanitized failures, and no automatic fallback.
- Added signed trusted-evidence ingestion for repository snapshots and adapter observations. `PolicyEngine` now rejects unsigned runtime evidence by default; raw records require an explicit test-only flag.
- Added descriptor-anchored Linux snapshot generation and a Linux/WSL launcher using user/net/pid namespaces, Landlock filesystem/TCP denial, clean environment, exact credential references, executable allowlist, timeout, and fail-closed preflight.
- Added deterministic cross-deployment evaluation with signed sanitized evidence and live reference adapters for loopback Ollama and broker-owned Claude CLI.
- Captured a passing live suite across Ollama 0.32.0 / Qwen3 0.6B and Claude Code 2.1.202 / Claude Sonnet 5. Raw prompt, output, endpoint, credential, path, provider body, session, and UUID values are absent from retained evidence.
- Removed the DGX dependency from canonical deployment templates and marked the old DGX inventory as historical/unavailable.
- Final gate: 172/172 `unittest`, full `pytest`, compileall, canonical validation, projection drift check, doctor, and diff check pass. Exact limits remain documented in the M2 completion report.

## [2026-07-15] implementation | M2 deterministic cross-deployment evaluation runner

- Added one vendor-neutral runner protocol for the same immutable suite across pinned local and cloud adapters; deterministic mocks exercise the protocol without network access or provider credentials.
- Normalized only Unicode/newline transport variance, retained output and usage differences, and required explicit per-case usage tolerances.
- Emitted schema-valid `AdapterConformanceProfile` observations plus canonical HMAC-signed evidence binding suite, exact identities, safe probe results, pairwise comparison, and observation digests.
- Kept prompts, outputs, endpoints, provider bodies, exception text, credentials, and paths out of evidence. Timeout is fail-closed for evidence; physical request cancellation remains a real-adapter obligation.
- Focused parity, output/usage divergence, timeout, identity mismatch, deterministic reproduction, and tamper tests pass 5/5.
- M2 remains open: mocks are implementation evidence, not live DGX/cloud evidence. Pinned deployments, trusted ingestion, OS credential/egress isolation, and one passing real suite digest are still required.

## [2026-07-15] implementation | M2.5 embedded durability completed

- Upgraded the authority schema to v3 with full immutable event baselines, store-generated native run events, deterministic replay, exact lifecycle/producer/issuer/subject/result reconciliation, and terminal full-projection checkpoints.
- Removed the broker's policy/budget authority. The typed embedded orchestrator now re-evaluates through its configured policy engine and executes atomic PREPARE, filesystem-only read, artifact fsync/proof, and SUCCESS/FAILURE.
- Adopted explicit `no_retry` recovery: an expired PREPARE cannot repeat I/O, exact fencing epoch is required, byte reservations are released, and spent tool attempts remain spent. Added real process-exit and concurrent writer/verifier tests.
- Added a private content-addressed artifact store with streamed digest/length, private temporaries, fsync, atomic no-clobber install, HMAC availability proofs, reopen byte verification, and safe crash-temp cleanup.
- Added authenticated v2→v3 migration without synthetic history, immutable read-only backup verification, authenticated online backup/no-overwrite restore, historical HMAC keyring, atomic dual-auth rotation with stable path-HMAC, external anchor chains, and optional startup anchor enforcement.
- Multi-agent P0 reviews covered event/reducer semantics, orchestrator authority, crash/recovery, artifact durability, migration, backup/rotation/anchor, and negative-test gaps. The completed boundary and its remaining limitations are recorded in `docs/research/2026-07-15-m2.5-completion-report.md`.
- Full suite contains 146 tests. M2 remains open only for pinned DGX/cloud adapters, identical cross-deployment evaluation, trusted snapshot/observation ingestion, and OS network/credential isolation.

## [2026-07-15] implementation | M2.5 pure run-event reducer checkpoint

- Extracted all run and tool lifecycle transitions into immutable `RunProjection` plus the side-effect-free `reduce_run_event` function; `RunEventChain` now delegates to this shared reducer instead of owning a second transition implementation.
- Kept producer capability, issuer, sequence, timestamp, and digest-chain checks at the event-ingress boundary while making the transition core reusable for durable SQLite replay and verification.
- Closed the `tool.failed` semantic gap: both completed and failed terminal tool events now require a `resultDigest`, preventing a failed event from being detached from its exact `ToolExecutionOutcome`.
- Added direct reducer tests for deterministic output, canonical tool projection ordering, caller-input immutability, and failure without partial state mutation.
- Full suite passes 116 tests; `compileall` and `git diff --check` are green.
- Next: define explicit event-history bootstrap mode, durable producer identity, atomic append/replay, and event integration into plan activation plus repository PREPARE/COMMIT without synthesizing missing historical events.

## [2026-07-15] implementation | M2.5 authoritative plan, budget, and repository-operation store

- Upgraded the fresh-store schema to v2 with authoritative `runs`, `plans`, `budgets`, `operations`, `budget_reservations`, `run_events`, and authenticated `authority_revisions`; legacy schema migration remains an explicit future ceremony rather than an implicit rewrite.
- Implemented exact plan issuance/activation, one active plan, initial-input accounting, and a deadline derived from immutable plan creation time that survives reopen and never extends on reclaim.
- Implemented atomic repository-read PREPARE: exact plan/snapshot/request/decision/intent binding, single-use allow consumption, conditional tool/input budget spend, content-free intent, reservation, and bounded lease in one `BEGIN IMMEDIATE` transaction.
- Implemented success/failure COMMIT, exact receipt/artifact/error/outcome reconciliation, exactly-once logical outcome/accounting, byte commit/release, tool-attempt preservation, lease reclaim with fencing epochs, recovery scan, and deterministic fail-closed abort after deadline.
- Replaced guessable plain path hashes with store-scoped domain-separated HMAC references; raw path/content remain absent from records, audit, DB, WAL, and SHM tests. Failure records are code-owned and reject arbitrary `causeRef`/details.
- Added distinct opaque policy/broker composition capabilities, exact policy/profile provenance checks, bounded owner IDs, authority-managed record APIs, and coherent single-snapshot verification across concurrent connections.
- Multi-agent adversarial review found and drove fixes for orphan nonces, mutable decision projection tampering, deadline-bypassing leases, policy provenance bypass, failure-metadata leakage, unauthenticated lease claiming, managed-record self-corruption, mixed-snapshot verification, and post-deadline stuck reservations.
- Full suite passes 112 tests; `compileall` and `git diff --check` are green. Canonical CLI validation/projection/doctor checks are rerun after this documentation update.
- Remaining M2.5 work: durable event/checkpoint reducer integration, typed store→broker orchestrator, opaque/encrypted retry payload handle or explicit no-retry profile, process-kill crash matrix, v1 migration, artifact availability proof, external audit anchor, and durable multiprocess issuer identity.

## [2026-07-15] implementation | M2.5 durable journal foundation

- Added content-free `ToolExecutionIntent`, `RepositoryReadReceipt`, `ToolExecutionOutcome`, and `RunCheckpoint` contracts for a crash-consistent PREPARE/read/COMMIT protocol.
- Implemented `SQLiteRuntimeStore` for allowlisted safe records and durable single-use decisions with WAL, `synchronous=FULL`, `BEGIN IMMEDIATE`, private POSIX permissions, immutable IDs, canonical bytes, exact idempotency, and UTC expiry.
- Added a global SHA-256/HMAC audit chain plus reconciliation back to records, decisions, and nonces; wrong keys, row/audit tampering, record+digest rewrites, and reopening a consumed decision fail closed.
- Raw `ToolRequest`, `RepositorySnapshot`, prompts, tool content, and credentials are rejected from the journal; privacy tests scan database/WAL/SHM files for a sentinel path.
- Independent agent design defined the next authoritative SQLite schema, two-transaction repository-read orchestration, recovery rules, and model adapter/endpoint/egress boundary.
- Full suite now passes 96 tests; compile, canonical validation, projection drift, doctor, and diff checks remain green.
- Remaining: migrate active run/event/budget authority into SQLite, crash-injection recovery, external audit anchor, authenticated snapshot/observation ingestion, and model adapter/isolation work.

## [2026-07-15] implementation | M2 embedded enforcement and read-only broker slice

- Implemented the embedded default-deny `PolicyEngine`: exact route/observation/tool intersection, immutable plans, single-use expiring decisions, no fallback, typed denials, full canonical schema defense, and future-time rejection.
- Implemented a capability-scoped `RunEventChain` with digest linkage, strict producer/outcome semantics, correlated tool lifecycles, explicit cancellation, success/exhaustion preconditions, and terminal-state enforcement.
- Implemented one runtime-owned atomic `BudgetLedger` per active plan, including initial-input accounting, concurrent request limits, monotonic duration, model-usage accounting, and input-byte reservations.
- Added the `RepositorySnapshot` contract and bound it into `RunPlan`; unknown, protected, D4, higher-class, or changed entries fail closed.
- Implemented the Linux/WSL `repository.read` broker with `openat2`, root-descriptor anchoring, symlink/magiclink/mount denial, hardlink denial, O_PATH preflight, regular UTF-8 file enforcement, size/digest checks, and replay-safe authorization.
- Independent multi-agent review found and drove fixes for optional budget fields, spoofable event producers, invalid tool/event ordering, hardlink aliasing, data-class escape after reads, resettable ledgers, byte-reservation races, and broker close/FD reuse.
- Full suite now passes 86 tests; `compileall`, canonical validation, projection drift check, doctor, and `git diff --check` are green.
- Proof boundary remains explicit: no model adapter, OS egress/credential isolation, durable audit/state, signed observation/snapshot attestation, or Windows/macOS broker is claimed.

## [2026-07-15] implementation | M2 runtime contract foundation

- Added the separate `runtime.ai.ecosystem/v1alpha1` contract namespace and schemas for run requests, immutable plans, tool requests, policy decisions, sanitized events, artifacts, typed errors, and observed adapter capabilities.
- Added a strict broker-owned `repository.read` argument contract and sanitized runtime validation that never echoes offending untrusted values.
- Required exact identity and observed-capability references before any deployment can be enabled; placeholder DGX/cloud deployments remain disabled.
- Strengthened logical-role validation for zone, data-class intersection, and artifact-trust compatibility; removed the unverified DGX candidate from the `review.private` role.
- Documented normative D/A/Z/P semantics, immutable policy binding, M2 proof limits, and the continued absence of a runtime PEP/broker.
- Added 13 runtime contract tests and 2 canonical cross-contract tests; full validation, projection drift check, and legacy tests remain green.

## [2026-07-15] inventory | ai-legal-claude upstream snapshot

- Cloned `zubair-trabzada/ai-legal-claude` to `/home/snow/projects/ai-legal-claude` at commit `19ece98df260c4c645bdd750f6e2eb48af2bd6c4`.
- Downloaded and statically reviewed source only; no global Claude skills/agents, Python dependencies, model calls, or legal-document processing were installed or executed.
- Classified the repository as a Claude-specific prompt/checklist corpus, not a legal model, compliance authority, trusted skill package, or active deployment.
- Recorded missing skill/agent frontmatter, the broken PDF interface contract, unsafe installer/uninstaller ownership, absent license/tests/evaluations, confidentiality and prompt-injection risks, and legal overclaims.
- Preserved the useful clause taxonomy, workflow decomposition, report patterns, and a gated vendor-neutral adoption path.

## [2026-07-15] inventory | NVIDIA NeMo labs-molt upstream snapshot

- Cloned `NVIDIA-NeMo/labs-molt` to `/home/snow/projects/labs-molt` at commit `a016f4eeb71d024a1bfb11f921d5cf2c415aaa00` (`version.txt` 0.1.2).
- Downloaded and reviewed source and Git history only; no model weights, datasets, dependencies, containers, Ray services, vLLM engines, or GPU workloads were installed or executed.
- Verified Python compilation and shell-script syntax; inventoried 19 unit-test files with 127 test functions without claiming full GPU validation.
- Classified Molt as an external experimental training/evaluation node, not the vendor-neutral ecosystem core or an active deployment.
- Recorded its nested agent/learning loops, token-exact trajectory contract, async training strengths, maturity limits, hardware assumptions, supply-chain risks, and gated promotion path.

## [2026-07-15] research | Loop and Harness article verification

- Moved the supplied Markdown from Downloads into `docs/research/sources/` unchanged and recorded SHA-256 provenance.
- Inspected the complete text and all five linked images; confirmed that promised configuration blocks are absent from the archive.
- Verified product claims against current Claude Code documentation, the official MCP specification, Anthropic engineering sources, and arXiv:2606.10209.
- Accepted the harness/loop separation and context/verification/state principles; rejected the seven-file layout as a universal contract.
- Recorded corrections for settings precedence, `.mcp.json`, auto-memory, hooks, reviewer independence, benchmark scope, and indefinite loops.

## [2026-07-15] inventory | OpenResearcher upstream snapshot

- Cloned `TIGER-AI-Lab/OpenResearcher` to `/home/snow/projects/OpenResearcher` at commit `785fd6ba5fcbc068daa4a2f07bbe0964f2983c86`.
- Downloaded source and Git history only; no model weights, trajectories, corpus, embeddings, or benchmark datasets.
- Classified it as an external experimental research node, not an ecosystem core or active deployment.
- Recorded useful patterns, evidence limitations, security boundaries, and a gated future promotion path.

## [2026-07-14] docs | Loop engineering contract

- Distinguished execution, automation, and learning loops.
- Defined the bounded LoopDefinition contract, independent gate, state trust layers, budgets, hard stops, approval, and audit requirements.
- Added L0–L5 maturity levels and fail-closed promotion rules.
- Selected `wiki-health-check` as the first L2 observe/report-only candidate; kept `ml-autoresearch` second behind experiment and DGX resource safeguards.
- Recorded that candidates are not runtime services until M2–M4 enforcement and evaluation boundaries exist.

## [2026-07-14] implementation | M1 contracts/compiler foundation

- Added `ai.ecosystem/v1alpha1` canonical `.ai/` contracts and JSON Schemas.
- Implemented `eco init/validate/audit/diff/render/doctor/lock/uninstall`.
- Added safe projection ownership, explicit adopt/force, backups, drift check, and rollback-aware uninstall.
- Added sanitized secret-reference validation, cross-contract checks, unit tests, and CI.
- Reframed LiteLLM/DGX as optional adapters/profiles; central service and multi-agent runtime remain deferred.
- M2 read-only PEP/broker is the next milestone; no production-enforcement claim is made.

## [2026-07-14] chore | Ініціалізація екосистеми (Phase 0)

- Створено hub-репо: AGENTS.md (конституція), MAP.md (карта вузлів), каркаси skills/ mcp/ agents/ loops/ wiki/
- Рішення: хаб — окремий репо; dgx_spark лишається вузлом «машина DGX»
- Кандидати перших loops: wiki-health-check (🟢), ml-autoresearch (🟢)
