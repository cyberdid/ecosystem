# Source review: “Loop and Harness engineering”

**Reviewed:** 2026-07-15
**Reviewer:** Codex using the `academic-research-suite` source-verification, synthesis, and devil's-advocate workflow
**Status:** evidence review; not an architecture decision or runtime implementation
**Raw source:** [archived Markdown](sources/loop-and-harness-engineering-7-files-5-steps-every-config-in.md)
**Original post:** [ArchiveExplorer on X](https://x.com/ArchiveExplorer/status/2071192832455430283)
**Raw-source SHA-256:** `52F0E79C6D69E6E9318303DCEDBCC62F7DB2FA62EBD37F0DB18A8EF8054F8A55`

## Research question

Which ideas in the article are reliable enough to inform a vendor-neutral AI ecosystem, which are Claude Code implementation details, which claims are overstated or incorrect, and what—if anything—should change in the ecosystem Loop/Harness contract?

## Executive verdict

The article provides a useful teaching model:

```text
harness = stable execution environment and constraints
loop    = bounded observe/plan/act/verify/state/stop process
```

That distinction is worth keeping. Its strongest practical ideas are explicit goals, small high-signal context, tool boundaries, durable state, independent verification, external scheduling, and failure-aware stopping.

The proposed “seven files” are **not** a universal harness standard. They mix Claude Code configuration, directories, project state, MCP transport configuration, and scheduler concerns. Several paths and precedence rules are wrong or outdated, and several empirical results are generalized far beyond the experiments that produced them. The article should therefore remain a secondary design input—not a template to copy verbatim and not a canonical source for this project.

Our current `wiki/loops.md` contract is materially stronger because it adds capabilities, policy decisions, approval, budgets, immutable gates, idempotency, audit, typed incomplete outcomes, and hard stops. No canonical `.ai/` contract should be replaced by the article's layout.

## Method

1. Preserved the supplied Markdown unchanged as an untrusted raw source and recorded its SHA-256.
2. Read the complete text and inspected all five remotely referenced images.
3. Compared product claims against current official Claude Code documentation.
4. Checked the cited context-engineering paper and Anthropic multi-agent article at their primary sources.
5. Checked MCP security and authorization claims against the official MCP specification and guidance.
6. Mapped the surviving ideas to the current ecosystem architecture.
7. Performed an adversarial review of both the article and our proposed interpretation.

Evidence labels used below:

- **Verified:** directly supported by a relevant primary source.
- **Partially supported:** core idea holds, but wording, scope, or implementation detail is inaccurate.
- **Unsupported/overstated:** plausible opinion presented as fact, or evidence does not justify the scope.
- **Incorrect:** conflicts with current primary documentation.
- **Time-sensitive:** repository counts, stars, versions, or product behavior that can change.

## What the article actually proposes

The article calls these the seven harness pieces:

1. `CLAUDE.md`
2. `.claude/settings.json`
3. hooks
4. `.claude/agents/`
5. `.claude/skills/`
6. `.mcp.json`
7. `MEMORY.md` plus a knowledge vault

It then puts a five-part process on top:

1. goal specification;
2. plan → act → verify;
3. subagent fan-out;
4. scheduler and persistence;
5. failure modes.

This is not a clean five-step state machine. “Failure modes” is an analysis category, not an execution step; fan-out is optional; scheduling belongs to automation orchestration rather than every execution loop. The useful invariant underneath the rhetoric is smaller:

```text
bounded goal → authorized attempt → objective verification
             → durable evidence → continue or stop by policy/budget
```

## Claim verification matrix

| Article claim | Verdict | Evidence and correction | Ecosystem implication |
|---|---|---|---|
| Harness and loop are distinct layers. | **Supported as a design model** | Stable configuration and runtime constraints are different from the iterative control flow. This is a sound architectural separation, though not an official seven-file standard. | Keep separate canonical contracts, runtime enforcement, and LoopDefinition. |
| The harness is the `.claude/` folder. | **Incorrect as a general definition** | Even Claude Code stores project `.mcp.json` at repository root, local/user MCP state in `~/.claude.json`, and auto memory under `~/.claude/projects/<project>/memory/`. Other vendors use different layouts. | `.claude/` is one vendor projection, never the ecosystem source of truth. |
| There are roughly seven required harness items. | **Unsupported heuristic** | Official Claude documentation describes multiple extension mechanisms but does not require this exact set. The list contains both files and directories and omits rules, commands/workflows, local settings, plugins, sandbox/policy, evals, and runtime controls. | Define capabilities and contracts by semantics, not by a fixed file count. |
| `CLAUDE.md` loads every session and should hold standing project context. | **Verified with nuance** | Claude Code loads applicable `CLAUDE.md` files at session start; nested files may load on demand. Files are concatenated context, not strictly enforced policy. Both `./CLAUDE.md` and `./.claude/CLAUDE.md` are valid project locations. | Generate a concise Claude projection from canonical instructions; do not treat it as enforcement. |
| `CLAUDE.md` must live at repo root. | **Incorrect** | Current docs permit `./CLAUDE.md` or `./.claude/CLAUDE.md`, plus user, managed, local, and nested forms. | Projection compiler chooses the appropriate adapter path. |
| Keep `CLAUDE.md` under 300 lines. | **Partially supported heuristic** | Current official guidance says to keep it under about **200** lines and move conditional/reference content to rules or skills. A line count is a rule of thumb, not a correctness boundary. | Budget always-on context and test adherence instead of enforcing a universal line limit. |
| The cited paper shows completion fell from 91.6% to 71% “purely from oversized standing context.” | **Incorrect interpretation** | arXiv:2606.10209 compared full conversation/tool history with last-five-tool-pair pruning plus summarization in a 50-task Dynamics 365 expense benchmark. It did not study `CLAUDE.md` size. GPT-5 improved from 71.0% to 91.6%; Claude Sonnet 4.5 moved from 92.0% to 94.5% for the comparable pruned vs summarized conditions. | Adopt context curation as a hypothesis to evaluate per workload; do not convert 91.6% into a universal policy. |
| Settings precedence is `managed > project > local > user`. | **Incorrect/incomplete** | Current order is `managed > command-line > local project > shared project > user`. Array settings can merge rather than replace. | Compiler and diagnostics must model each vendor's real merge semantics and version. |
| Project settings always override personal settings. | **Partially supported** | Shared project settings override user settings, but local project settings override shared project settings, managed policy overrides all, CLI can override non-managed layers, and arrays may merge. | Avoid simplifying precedence into one slogan. Render and audit effective configuration. |
| Put secrets in `.claude/settings.local.json`. | **Unsafe recommendation** | Gitignored plaintext reduces accidental commits but is not a secret manager. MCP guidance says not to log credentials and to store secrets securely outside source control. | Canonical config stores secret references only; runtime resolves them through an approved secret provider. |
| Hooks are deterministic scripts for lifecycle events. | **Verified with limits** | `PreToolUse`, `PostToolUse`, `Stop`, and other events exist. `PreToolUse` can block; `PostToolUse` runs after side effects and cannot undo them. Hooks can fail, time out, produce malformed output, or be bypassed outside that client. | Use hooks for adapter-local automation and defense in depth, not as the sole policy enforcement point. |
| A post-edit formatting hook creates a “policy floor.” | **Overstated** | It can create repeatable formatting inside Claude Code, but it neither authorizes actions nor enforces behavior across other agents, direct shell access, CI, or external systems. | Policy belongs in an external PEP/broker plus filesystem/network boundaries and negative tests. |
| Subagents run in isolated context. | **Verified** | Claude Code subagents have separate context and return a result/summary to the parent. | Use isolation for context control and task decomposition where it adds value. |
| A reviewer in the maker context always agrees; fresh context closes the failure mode. | **Unsupported absolute** | Isolation reduces contamination and path dependence but does not guarantee independence. Same-model reviewers can share blind spots, accept persuasive errors, or use the same flawed rubric. | Prefer deterministic gates; use LLM review as supplementary evidence and measure disagreement/false acceptance. |
| Skills progressively load only when needed. | **Mostly verified** | By default, descriptions are visible at session start and full skill content loads when used. Manually hidden skills can have zero startup cost. Skills explicitly passed to subagents are preloaded. | Keep capability descriptions precise and measure context cost; don't assume every runtime uses identical loading. |
| `.mcp.json` declares project MCP servers. | **Verified** | Claude Code stores team-shared project MCP configuration in `.mcp.json` at project root and asks for initial project-server approval. | Treat this as a generated transport adapter, not an authorization policy. |
| `.mcp.json` belongs inside `.claude/`. | **Incorrect** | Official Claude Code documentation places project `.mcp.json` at repository root. | Do not reproduce the article's directory claim. |
| Log every MCP call before enabling write scope. | **Useful but insufficient recommendation** | MCP guidance supports audit logs, confirmation for sensitive operations, least privilege, input validation, timeouts, sandboxing, and secure authorization. Logging alone neither prevents a write nor protects secrets. | Broker tools through capability checks, approval, scoped credentials, sandboxing, redaction, audit, and rollback/idempotency controls. |
| A repository `MEMORY.md` is the seventh required piece. | **Incorrect as a Claude Code requirement** | Current Claude auto memory uses `~/.claude/projects/<project>/memory/MEMORY.md`; it is machine-local and loaded only up to 200 lines/25 KB. A project may separately choose versioned state files, but those have different trust and review semantics. | Separate run state, experiment ledger, curated project memory, procedural skills, and append-only audit. |
| Memory should be pruned rather than append-only. | **Supported principle** | High-signal context curation is supported by Anthropic guidance and the cited benchmark. But pruning must preserve provenance and must not silently rewrite audit history. | Curated memory may compact; audit and experiment ledgers remain append-only. |
| Context accuracy “collapses around 200K tokens.” | **Unsupported universal threshold** | Anthropic describes context rot as a performance gradient that varies by model and task, not a universal 200K cliff. The cited paper measures one workload and specific policies. | Detect task-specific saturation, stale state, and no-progress through evals and runtime metrics. |
| Goal and progress state should live outside the model context and be reread. | **Supported pattern** | Durable external state helps recovery and reduces dependence on one conversation, but files remain untrusted mutable inputs unless protected and validated. | Version goal/evaluator, type the state, protect immutable fields, and record provenance. |
| Plan → act → verify is the minimum viable loop. | **Supported but incomplete** | It captures feedback, but production safety additionally requires authorization, budget, side-effect control, incident handling, idempotency, and explicit stop outcomes. | Keep the richer ecosystem state machine. |
| Verification should be separate from generation. | **Supported with qualification** | Separation is valuable; a separate LLM is not necessarily an independent gate. | Actor cannot modify protected tests, evaluator, baseline, rubric, or acceptance threshold. |
| Multi-agent research achieved +90.2%. | **Verified, narrowly scoped** | Anthropic reported its Opus 4 lead + Sonnet 4 subagent system outperforming single-agent Opus 4 by 90.2% on an **internal research eval**, especially breadth-first tasks. The eval is internal, model-specific, and token usage explained much of the performance variance. | Fan-out is a costed strategy for decomposable breadth, not a default for every task. |
| One large context cannot handle ten jobs; ten small ones can. | **Overstated** | Parallel isolated contexts can improve breadth and reduce parent-context pressure, but coordination, duplicated work, correlated errors, latency, and token cost grow. | Spawn workers only when tasks are independent and synthesis has a defined evidence contract. |
| Scheduler should be dumb and persistence external. | **Good engineering heuristic** | Keeping trigger mechanics separate from agent reasoning improves observability and recovery. It is not a Claude Code hook feature and not mandatory for manual execution loops. | Model scheduler as LoopDefinition `trigger`; make state transitions explicit and idempotent. |
| Missing any one of the seven files causes a specific degradation. | **Unsupported** | Many successful tasks need only a subset; some controls belong outside these files. The correct set depends on side effects, risk, duration, repeatability, and vendor. | Use maturity/risk profiles, not completeness by file count. |
| Build the seven files once and “the loop runs forever.” | **Incorrect and unsafe** | Dependencies drift, credentials expire, policies change, evaluators regress, resources exhaust, and indefinite loops amplify failure. | Every loop needs budgets, health checks, versioned contracts, owner, kill switch, and terminal outcomes. |

## What survives into the ecosystem design

### Accept

1. **Separate harness from loop.** Stable capabilities and constraints should not be confused with the iterative controller.
2. **Keep goals and evidence durable.** A run must recover without trusting a model's hidden conversational state.
3. **Curate context.** Prefer the smallest sufficient, high-signal context; retrieve detail on demand.
4. **Verify before repeating.** Repetition without a gate compounds confident errors.
5. **Use context isolation deliberately.** Workers and reviewers may get isolated contexts when that reduces contamination or enables breadth.
6. **Separate scheduling from reasoning.** Triggers should initiate a versioned loop definition, not contain opaque decision logic.
7. **Treat failure as typed evidence.** No-progress, exhaustion, policy denial, and dependency drift must stop safely.

### Accept only with stronger boundaries

- Hooks are useful adapter automation, but the trusted policy decision must be external.
- LLM reviewers can cover semantic ambiguity, but deterministic tests remain the hard gate where possible.
- Memory can be compacted, but raw evidence and audit history cannot be silently rewritten.
- MCP is a transport/integration layer; authorization, approval, credentials, and audit remain host/runtime responsibilities.
- Multi-agent fan-out is optional and justified by decomposition quality and measured cost, not fashion.

### Reject as ecosystem doctrine

- exactly seven files;
- `.claude/` as the universal harness;
- vendor files as canonical truth;
- a fixed context-size cliff;
- “fresh reviewer = independent verification”;
- unrestricted or indefinite loops;
- dynamic GitHub star counts as technical evidence;
- direct cloning of large agent/skill/MCP collections as a design method.

## Mapping to the current ecosystem

| Article concept | Ecosystem equivalent | Decision |
|---|---|---|
| `CLAUDE.md` | Projection from `.ai/instructions.yaml` plus project docs | Adapter output, concise and regenerable |
| `settings.json` | Deployment/tool/capability projections | Vendor-specific output; validate effective merge |
| hooks | Local adapter guardrails and automation | Defense in depth, never sole PEP |
| agents | Optional isolated workers | Registered capability with budgets and evidence contract |
| skills | Reusable procedures/knowledge | Reviewed promotion; scoped loading; provenance required |
| `.mcp.json` | MCP adapter generated from approved tool declarations | Transport config only; no embedded secrets |
| `MEMORY.md` | Run state, experiment ledger, curated memory, audit | Four separate trust/lifetime layers, not one file |
| `PROMPT.md` goal | LoopDefinition `task_schema`, objective, result contract | Versioned and immutable during run |
| verifier | LoopDefinition `gate` | Prefer deterministic; protect evaluator inputs |
| cron/systemd/queue | LoopDefinition `trigger` plus scheduler | External, observable, idempotent |
| run log | Trusted run/experiment ledger | Append-only provenance and typed outcomes |

This mapping preserves portability across local models, Claude, Copilot, Codex, or future providers. A provider-specific projection can disappear without erasing the objective, capability model, security policy, state schema, evaluator, or evidence.

## Revised vendor-neutral Harness/Loop contract

The article's mental model becomes useful after replacing file names with semantic layers:

```text
Harness
├── canonical objective and instruction contracts
├── deployment/provider adapters
├── capability and tool registry
├── policy enforcement and approval boundary
├── filesystem/network/process isolation
├── typed state, secrets, provenance and audit
├── deterministic evals and protected gates
└── budgets, observability, incident owner and kill switch

Loop
trigger
→ acquire versioned task and budget
→ load approved context and trusted state
→ policy decision
→ one bounded attempt
→ independent gate
→ persist evidence
→ succeed, retry within budget, or stop/escalate
```

The harness is therefore not a folder. It is the set of enforced contracts and runtime boundaries that make an attempt safe, reproducible, observable, and portable. Files are merely one projection of that harness.

## Devil's-advocate review

The ecosystem can also fail by overcorrecting the article:

- A complete enterprise control plane is unnecessary for a read-only, manual, disposable task.
- Excessive schemas and indirection can make simple workflows harder to debug than a script plus tests.
- Deterministic gates are not always available for research, design, and semantic quality.
- Provider-neutral abstractions can collapse to the lowest common denominator and hide valuable native capabilities.
- External state and audit add storage, privacy, retention, and governance burdens.
- Multi-agent isolation can improve breadth while degrading synthesis and exploding cost.

The remedy is progressive maturity, already reflected in L0–L5 levels: start with the smallest harness justified by the risk, then promote only after measured evidence. Vendor-specific capabilities may exist behind explicit adapters; they must not silently become canonical semantics.

## Recommended actions

### Now

- Keep this article and review in the research layer only.
- Add the verified conclusions to the Loop wiki, without copying its seven-file layout.
- Preserve the current bounded LoopDefinition and M2 read-only PEP/broker priority.

### During M2–M3

- Define provider projections for Claude/Codex/Copilot without making any projection canonical.
- Implement effective-configuration inspection so precedence and drift are observable.
- Treat MCP/tools as capability requests evaluated by an external policy decision point.
- Add secret-reference validation and prevent literal credentials in generated config.
- Make gate, budget, stop reason, and result schemas executable and negative-tested.

### Before scheduling any loop

- Establish a deterministic or calibrated gate.
- Protect objective, evaluator, baseline, and held-out data from actor writes.
- Set attempt/time/token/cost/resource budgets and no-progress detection.
- Require idempotency and partial-side-effect reporting.
- Record owner, approval path, audit events, and kill switch.
- Run repeated fixed-fixture evaluations and measure false acceptance.

## Source-quality notes

- The supplied Markdown is an external secondary source and contains promotional language and absolute claims.
- Multiple promised config/code blocks are absent from the Markdown after phrases such as “Minimal working shape.” The five linked images were inspected; they contain a cover, repository screenshots, and a paper table, not the missing “every config” examples. The archive is therefore incomplete relative to its title.
- Repository star counts are snapshots that change continuously and were not treated as evidence of quality, security, or suitability.
- The cited 2026 arXiv paper is a recent preprint. Its benchmark is narrow and its generalization section explicitly calls for broader work.
- Anthropic's 90.2% result comes from an internal evaluation, limiting independent reproducibility and external validity.
- Product documentation changes; findings about Claude Code are accurate to the review date and should be rechecked before generating adapters.

## Primary sources

- Claude Code, [How Claude remembers your project](https://code.claude.com/docs/en/memory)
- Claude Code, [Settings](https://code.claude.com/docs/en/settings)
- Claude Code, [Explore the `.claude` directory](https://code.claude.com/docs/en/claude-directory)
- Claude Code, [Extend Claude Code](https://code.claude.com/docs/en/features-overview)
- Claude Code, [Hooks reference](https://code.claude.com/docs/en/hooks)
- Claude Code, [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp)
- Anthropic, [Effective context engineering for AI agents](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
- Anthropic, [How we built our multi-agent research system](https://www.anthropic.com/engineering/multi-agent-research-system)
- Lodha et al., [Less Context, Better Agents](https://arxiv.org/abs/2606.10209), arXiv:2606.10209 (preprint)
- Model Context Protocol, [Security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- Model Context Protocol, [Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- Model Context Protocol, [Tools security considerations](https://modelcontextprotocol.io/specification/2024-11-05/server/tools)

## Local normative references

- [Loop engineering](../../wiki/loops.md)
- [Current architecture](../../wiki/architecture.md)
- [Roadmap](../../wiki/roadmap.md)
- [Architecture decisions](../decisions/README.md)
- [Loop candidate registry](../../loops/README.md)

## AI-use disclosure

Codex performed source extraction, claim comparison, synthesis, and adversarial review. No subagents were used because this task did not request delegation. Primary-source links and exact local provenance are provided so a human can reproduce the review. Conclusions marked as design recommendations are inferences, not findings from the cited studies.
