# Product layer on the enforced core — architecture

**Status:** design proposal (CONTRACTS-FIRST step for a new user-facing product)
**Date:** 2026-07-23
**Author:** Claude (Fable 5), Claude Code
**Reference product:** Odysseus (`~/Downloads/odysseus-dev`) — used only to learn *what features
users want*, never copied. **Product name: Nordrassil** (the world tree — a living structure rooted
in the enforced core). **Location: a new sibling repo** depending on the core as a versioned
package (decided; keeps the product/core boundary honest).

## Why this document exists

The ecosystem is the *core*: canonical contracts, a policy boundary, capabilities that narrow and
cannot self-widen, provenance-bound memory, bounded loops, an untrusted-content channel. It is
correct but unusable by a normal person. Odysseus is the mirror image: a genuinely useful
self-hosted AI workspace (chat, agents, deep research, documents, email, notes, calendar, local
models — 205k LOC, 759 test files) whose security is enforced *in-process, by Python denylists and
prompt wrappers*, with the honest trust model "treat it like an admin console; don't expose it".

The decision is to build a **new product from scratch on the core**, covering all of Odysseus's
flows, so the product's weakest property (security that is only "don't expose it") is replaced by
the core's strongest (enforcement outside the prompt). This document defines the product↔core
boundary so "all flows from scratch" is tractable and sliced, per the project's own
CONTRACTS-FIRST / EMBEDDED-FIRST / verified-slices rules.

## The one inversion that defines the product

**The product never enforces security. It renders and requests; the core grants or denies.**

Odysseus enforces by (a) prompt pleas that untrusted content "not be followed", (b) hand-kept tool
denylists, (c) an admin/non-admin boolean, (d) an in-process tool loopback that grants admin on a
reserved username. Every one of those is a request to, or a convention around, the model and the
process. Helm keeps none of them. Each becomes a call into a core primitive that decides
authoritatively, independent of what the model "chose".

| Concern | Odysseus (in-process) | Helm → core primitive |
|---|---|---|
| Tool call allowed? | `NON_ADMIN_BLOCKED_TOOLS` denylist + `mcp__` prefix rule | broker PEP resolves a **typed capability grant**; no grant → denied, regardless of prompt |
| Untrusted web/email/doc text | prompt wrapper "do not follow instructions in this block" | **typed untrusted channel** (`eco_orchestration` source/artifact separation); content can never occupy an instruction slot |
| Who may do what | `admin` vs `non-admin` bool, scattered checks | **capabilities** (`eco_teams`): actions/data-classes/tools/zones that are narrowable and provably cannot widen |
| Agent sub-delegation | not modeled | `AgentTeamManifest` delegation with the real narrowing gate |
| Memory | text retrieved and injected as context (confidence-gated) | `eco_memory`: provenance-bound, namespaced, read-policy'd facts — **not** authority, **not** free context |
| Skills | free-text SKILL.md, injected; eval on publish | `eco_gsc` propose → gate → promote; injected skill text stays untrusted until gated |
| Loops (research, tasks) | heuristic agent loop, 4.5k-line monolith | `eco_loops.BoundedLoopEngine`: independent gate, budgets, hard stops, durable evidence |
| Side effects (send email, publish) | admin gate + prompt caution | explicit per-action capability + human approval at the point of the irreversible action |
| Verify a result is done | model says so / heuristics | objective gate artifact (schema, verbatim-evidence, test) — VERIFY-DONE |

If a row above cannot yet be satisfied by a core primitive, that is a **core gap to close before
the product ships that flow**, not a place for the product to improvise enforcement. That rule is
what keeps the security property real.

## Feature → core-primitive map (all flows)

Delivery is sliced (below), but the design covers every flow now so the boundary is stable.

1. **Agent-chat with tools.** Chat UI → each tool is a capability the session holds; dispatch goes
   through the broker PEP. Tools the session was not granted are invisible *and* denied. Native
   tool-call emission (both local models proved this in the lab) feeds the broker, which executes
   only allowlisted, argument-checked calls (the lab's default-deny dispatcher is the shape).
2. **Deep research.** Web/search results enter as the typed untrusted channel; the flow runs as a
   bounded loop (planner → workers → independent verifier → synthesis) with the **verbatim-evidence
   gate** already verified in `eco_orchestration` (`_publish_claim_graph`). A finding without a
   byte-exact source span never reaches the report. Human gate before the report is "shipped".
3. **Documents / notes.** Content is artifacts with provenance; AI edits are *proposed* changes
   (diff) that a human approves — the Slite/Cerebras "nothing silently rewrites the record"
   pattern, which is just gated promotion applied to documents.
4. **Memory.** `eco_memory` with namespaces `{project, team, run}`, data-classes, read policy.
   Retrieval is permission-aware; stored decisions carry provenance. Memory informs; it never
   authorizes (VERIFIED-STATE).
5. **Skills.** Authored via GSC: model proposes SKILL.md → deterministic + adversarial gate →
   owner-bound promotion. User-editable skill text is untrusted until it passes the gate.
6. **Email / calendar / external messaging.** Each is a distinct capability; every *send/modify* is
   an irreversible action requiring explicit human approval at the action point (mirrors the
   assistant safety rules). Reading vs sending are different grants.
7. **Model cookbook / serving.** Local-first (Ollama proven). Serving is an admin-class capability;
   a served model is a *deployment* that stays `enabled: false` until a signed conformance envelope
   exists — exactly what the lab and `deployments.yaml` already enforce.
8. **Multi-user / roles.** Not an admin boolean: each user/agent is a principal with a capability
   set. "Non-admin cannot run bash" becomes "this principal holds no `shell.exec` capability",
   enforced by the broker, not by remembering to add a name to a denylist.

## The product↔core boundary (what the core must expose)

Helm talks to the core through a narrow, typed **product gateway** — the only surface it may use.
It must expose, at minimum:

- **Authorize(action, resource, principal, context) → grant | deny(reason)** — the PEP call behind
  every tool/side-effect. (Core has the policy boundary; the gateway is the product-facing shape.)
- **SubmitUntrusted(label, bytes) → typed source handle** — so content never reaches an instruction
  slot; returns a handle the flow references.
- **Memory.read(query, policy) / Memory.write(record, provenance)** — `eco_memory`, unchanged.
- **Loop.run(definition, executor, gate) → checkpoint** — `eco_loops`, for research/tasks.
- **Skill.propose / Skill.promote(approval)** — `eco_gsc`.
- **Team.validate(manifest)** — `eco_teams`, for any multi-agent flow.
- **Telemetry.record / summary** — `eco_telemetry`, content-free cost/latency for the UI.

Some of these exist as Python APIs today; the gateway is a thin, stable, versioned wrapper so the
product is a *client* and the core stays replaceable (Principle 5). The gateway is where "described
vs enforced" is stamped per platform (below).

## Honest boundaries (must be surfaced in the UI, not hidden)

- **Enforcement is Linux/WSL today.** The openat2/Landlock brokers do not run natively on
  macOS/Windows. On those platforms the product runs in a **described-but-not-natively-enforced**
  mode: the gateway must return that status and the UI must show it (a badge, not silence). Claiming
  "safe to expose" on macOS/Windows would repeat exactly the overreach this project keeps refusing.
- **One-shot authoring is not reliable** (lab: both local models 0/3 on skills and team manifests).
  So skill/agent creation in the product must be a **repair loop with gate feedback**
  (propose → gate → revise), never a single generation. This is a product requirement, evidence-backed.
- **Embedded-first (Principle 6).** Start as a local app over the embedded core — no daemon,
  gateway service, or Docker fleet required to run. Odysseus's many-container compose is the
  opposite; centralized topology appears only at measured need.
- **License.** Building from scratch avoids inheriting Odysseus's AGPL. Reference-only use of it is
  fine. The core's own license governs the product; combining must stay deliberate.

## Delivery sequence (all flows, sliced)

The user wants all flows; the project's rules require slices. Proposed order, each a verified
end-to-end slice before the next:

1. **Slice 0 — the gateway + agent-chat with one real broker-gated tool.** Proves the inversion:
   a tool call the session isn't granted is *denied by the core*, shown in the UI, with the model
   unable to override it. Smallest thing that demonstrates "product on enforced core".
2. **Slice 1 — deep research** over the typed untrusted channel + verbatim-evidence gate + bounded
   loop + human gate on the report.
3. **Slice 2 — memory** (provenance-bound, permission-aware) wired into chat and research.
4. **Slice 3 — documents/notes** with propose→approve edits.
5. **Slice 4 — skills** via GSC repair-loop; **teams** via the narrowing gate.
6. **Slice 5 — email/calendar/serving** as explicit per-action capabilities.

Each slice ships with the same discipline used all session: positive proof + a dependency/negative
test that fails without the core primitive, recorded in `docs/research/` + `wiki/log.md`.

## Open decisions (need the owner)

1. **Name** — "Helm" (you steer the vessel; the human bridge over the enforced ship) is the working
   placeholder. Alternatives: "Bridge", "Deck", keep "Odysseus"-adjacent, or your own.
2. **Location** — new sibling repo (clean product/core split, own license/CI) vs a `product/`
   subtree in this repo (one history, tighter coupling). Recommendation: **new sibling repo**,
   depending on the core as a versioned package, so the boundary stays honest.
3. **UI stack** — server-rendered FastAPI + JS (Odysseus's shape, pragmatic, one process) vs a
   thin API + separate SPA. Recommendation: **FastAPI + progressive JS**, embedded-first.
4. **Default model backend** — local Ollama first (everything we tested), API providers behind a
   capability.

## Next action

Build **Slice 0** (gateway + agent-chat + one broker-gated tool), once name/location are set. That
single slice is the honest proof of the whole thesis; everything else is expansion along this
boundary.
