# Loop and Harness engineering: 7 files, 5 steps. Every config inside

**Author**: Archive ([@ArchiveExplorer](https://x.com/ArchiveExplorer))
**Date**: 2026-06-28
**Source**: https://x.com/ArchiveExplorer/status/2071192832455430283

---

![Cover](https://pbs.twimg.com/media/HL2SvKHWgAAaZw2.jpg)

Most builders fight the loop. The loop is fine. The folder underneath isn't set up.
Open .claude/ in any working Claude Code project and you find roughly seven things doing the actual work: CLAUDE.md, settings.json, hooks/, agents/, skills/, .mcp.json, and a state file like MEMORY.md.
Most builders have opened one of those files. Maybe two. That is why their loops stall on the third iteration.
By the end of this article you will know what each file does, the five loop steps that ride on top, the three failure modes that kill most first attempts, and the single next file to add tonight.
No framework. No subscription. One walkthrough with exact paths and exact contents.
The harness is the floor. Pour it first.
Two layers, one setup
The harness is the .claude/ folder. It does not change between runs.
The loop is what runs inside it: a goal, an action, a verification step, a memory write, and a decision to keep going or stop.
The harness is the kitchen. The loop is the recipe.
Both fail without the other. A kitchen with no recipe is unused space. A recipe with no kitchen is wishful thinking.
Most builders treat the whole thing as one blob ("my agent setup") and miss that failures live in different layers.
Token blowups, prompt fatigue, dropped permissions: harness problems. Loops that never converge, verifications that pass garbage, scheduled runs that drift: loop problems.
Naming the layer fixes the diagnosis. You stop rewriting prompts when the real bug is a missing permission.
I thought building the loop first would teach me which harness files I needed. It was the other way around.
The harness sets what each iteration is allowed to do. Permissions decide whether the loop can write to disk. Subagents decide whether verification runs in a clean context.
Skills decide whether the loop can specialize. Hooks decide whether the loop even gets to fire on the trigger you wanted.
Without those decisions locked in, the loop guesses. When the loop guesses, it fabricates: invented files, invented commands, passing tests that pass nothing.
The harness stops the guessing. So the order is harness first, loop second, always.
The harness, file by file
CLAUDE.md
The first file Claude Code reads on every launch. Its contents become standing context for the entire session.
Put the project shape there: directory layout, language and framework, commands that actually work, conventions the agent must respect, and an explicit list of things it must not do.
Lives at repo root, not buried in docs. Minimal working shape:
 
The trap is bloat. The paper Less Context, Better Agents (arXiv 2606.10209) measured task completion dropping from 91.6% to 71% purely from oversized standing context.
Keep it under 300 lines. Prune it weekly. Every added paragraph is a tax on every future turn.
The canonical reference is centminmod/my-claude-code-setup, which ships three working CLAUDE.md shapes side by side.
 
settings.json
Where the tool allowlist, environment variables, and hook registrations live.
Two locations matter for daily work: .claude/settings.json at repo root for repo-scoped rules, and ~/.claude/settings.json for your personal defaults.
Scope hierarchy resolves managed > project > local > user, so project always overrides personal.
The first move that pays off in one afternoon is an allow array for read-only Bash and MCP calls:
 
The agent stops blocking on permission prompts for every ls, git status, cat. Destructive ops still gate.
Full key reference: Claude Code docs - Settings. Keep secrets in .claude/settings.local.json and gitignore it.
hooks
Deterministic scripts that fire on tool events: PreToolUse before a tool runs, PostToolUse after, Stop when the agent finishes a turn.
Registered inside settings.json with a matcher pattern and a shell command. Canonical first hook: a PostToolUse matching Edit|Write that pipes the file through prettier.
 
Every edit now exits in a known state. This is your policy floor.
Without hooks, every run is a vibe. Keep hooks silent on success, loud only on failure. Reference: Claude Code docs - Hooks.
subagents
Live under .claude/agents/ as markdown files with YAML frontmatter. Main agent invokes them through the Task tool. They run in a fresh context window.
Minimal verifier subagent:
 
The reviewer that lives inside the maker's context always agrees with itself. Pulling review into a fresh context closes the loudest failure mode.
Reference: wshobson/agents (37K stars) for 194 ready-made shapes. For an adversarial verifier with 11 named shortcut-checks (relaxed tests, swallowed errors, fake renames), pull moonrunnerkc/swarm-orchestrator.
 
skills
Live under .claude/skills/ as folders containing SKILL.md with YAML frontmatter.
Load progressively: at session start, only name and description enter context. Full body loads only when the agent decides the trigger matches.
 
This discipline keeps a fifty-skill library from costing fifty skills' worth of tokens on every prompt.
Canonical pattern: anthropics/skills (155K stars). Maximal pre-built kit: affaan-m/ECC (222K stars).
 
Three skills built when you hit the same task a third time beat fifty skills built speculatively from a tutorial.
MCP
Servers declared in .mcp.json at repo root. Model Context Protocol is the spec that lets the loop call out to live external tools.
Three rules: only servers your current work uses, prefer official ones for credentialed tools, never install five "just in case".
 
Anthropic-maintained set: modelcontextprotocol/servers (87K stars). 
Code-host integration: github/github-mcp-server (31K stars).
Live library docs (kills stale-API problems): upstash/context7 (58K stars). 
Discovery index: punkpeye/awesome-mcp-servers (89K stars).
The first mistake is enabling a server with write scope before you have a hook that logs every call.
state and memory
The seventh piece, the one most people skip until the third project goes sideways.
Shape: a MEMORY.md index file at a known path, plus a vault directory for project canon.
 
Memory holds what changes across sessions. Vault holds what does not.
For production-grade session compression (200K-token transcript -> 4K-token recap without losing load-bearing facts): thedotmack/claude-mem (84K stars).
Theory behind why this matters: Anthropic engineering on context engineering names the failure mode: context rot.
The first mistake is treating memory as append-only. Prune it every session, or it becomes the rot.
The loop, on top of the harness
1. Goal spec
The external contract that says what "done" looks like. Lives on disk, not in the agent's head. The loop re-reads it every iteration.
Name: PROMPT.md, AGENTS.md, or AGENT_SPEC.md. The re-read is what matters.
 
Without this file the agent drifts after about three iterations. Smallest possible reference: ghuntley/how-to-ralph-wiggum (1.7K stars) - PROMPT.md plus an IMPLEMENTATION_PLAN.md state file the loop updates in place.
When the spec is missing, failure looks like progress. Code is written, tests pass, the goal it solved is not yours.
2. Plan to Act to Verify
The minimum viable loop is three steps. The agent plans against the goal spec, executes, then a separate verification pass checks the result before the next iteration is allowed to start.
Fresh context each iteration is the Ralph pattern. State lives on disk in the spec file plus a running log.
 
Canonical patterns and CLI starters: cobusgreyling/loop-engineering (3K stars).
Production TypeScript reference with verifyCompletion: vercel-labs/ralph-loop-agent (805 stars).
Full installable Plan-to-Work-to-Review-to-Release cycle: Chachamaru127/claude-code-harness (2.9K stars).
Drop the verify step and confident garbage compounds. Every wrong output becomes the next iteration's input.
3. Sub-agent fan-out
When one goal branches into many independent sub-jobs (analyze 10 articles, fix 5 files, search 8 sources), the loop spawns parallel subagents. Orchestrator synthesizes.
One bloated context cannot do this. Ten small ones can.
 
Anthropic engineering on multi-agent research measured +90.2% on their internal eval against a single-agent baseline.
Official SDK: anthropics/claude-agent-sdk-python (7.4K stars). Heaviest public fan-out kit (60+ agent types, 314 MCP tools): ruvnet/ruflo (61K stars).
Skip the fan-out and the orchestrator drowns. One context loaded with ten jobs' worth of source material is the exact shape that triggers context rot.
4. Scheduler and persistence
What triggers the loop when you are not in the chair. cron, launchctl, systemd, a queue runner.
The scheduler is deliberately dumber than the agent. If the scheduler tries to think (branch on state, decide whether to skip), it fails silently for days.
 
Or as a launchd plist on macOS:
 
Persistence is the other half. Every iteration must serialize what it did, what it tried, what is next. Otherwise the scheduler wakes up to an agent that forgot the goal.
Pattern for promoting ad-hoc sessions into scheduled runs: Kanevry/session-orchestrator.
5. Failure modes
Three failure modes kill almost every first attempt:
(a) Confident garbage. Verify step missing or weak. Wrong outputs pass and compound across iterations.
(b) Context rot. Single long context where the model degrades past a threshold (Anthropic's term). Accuracy collapses around 200K tokens of accumulated history.
(c) Ralph Wiggum loops. Same iteration repeats because state on disk did not capture progress. The agent re-plans the step it already finished.
The Less Context, Better Agents paper (arXiv 2606.10209) measured full-history at 71% task completion versus prune-and-summarize at 91.6%, on a fraction of the tokens.
 
 
moonrunnerkc/swarm-orchestrator catalogs the 11 shortcuts agents take to fake done: relaxed tests, swallowed errors, fake renames, stub returns, comment-deletion-as-fix.
Memorize the names. You will recognize them in your own logs.

A complete minimal setup wires all seven harness files into a working loop. The shape of a project directory looks like this:
 
The wiring is one-directional. The harness defines the rules, the loop runs inside them, the state file connects iteration N to iteration N+1.
A single iteration walks the seven harness files and the five loop pieces in this order: cron fires run.sh, which calls claude -p. Claude Code reads CLAUDE.md and settings.json (harness 1, 2), applies the PostToolUse hook on every edit (harness 3), reads PROMPT.md and IMPLEMENTATION_PLAN.md (loop step 1), plans and acts (loop step 2), dispatches the verifier subagent in a fresh context (harness 4 + loop step 2 verify), writes the result back to IMPLEMENTATION_PLAN.md (loop step 3), updates MEMORY.md if a new preference was learned (harness 7), exits. Cron waits for the next tick (loop step 4).
If any of the seven harness files is missing, a specific loop step degrades. No CLAUDE.md and the planner re-derives the project shape every iteration. No verifier subagent and the verify step happens in the main context and always passes. No MEMORY.md and the same correction gets re-applied every Tuesday.
Build the seven harness files once. The loop runs forever.
What to do tonight
Open your .claude/ folder. Run:
 
Count the files.
If you see nothing or only settings.json, start with CLAUDE.md. Keep it under 300 lines. Copy a shape from centminmod/my-claude-code-setup.
If you have CLAUDE.md and settings.json but no agents/, add a verifier subagent next. Pull review out of the main context. Shape: wshobson/agents.
If you have agents/ but no skills/, promote one frequent task to a skill. The prompt you have copy-pasted three times this week. Read three SKILL.md files from anthropics/skills before you write your first one.
If you have all seven harness files but no loop running, pick one repeating job, write its goal spec, and put a Plan-Act-Verify loop on top. Closest installable starting point: Chachamaru127/claude-code-harness.
After choosing, do one thing: open the matching repo in a new tab and clone it.
The harness is the floor. Without it, every loop runs over a hole.

![](https://pbs.twimg.com/media/HL5U4TbWgAArdOa.jpg)

![](https://pbs.twimg.com/media/HL5VyAAWwAAZXAX.jpg)

![](https://pbs.twimg.com/media/HL5WWGsW4AAxnSd.jpg)

![](https://pbs.twimg.com/media/HL5ZlSkXgAA09wS.png)
