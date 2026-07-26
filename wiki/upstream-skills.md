# External skills and the Microsoft Skills reference

**Updated:** 2026-07-26
**Status:** pinned Microsoft snapshot reviewed; offline non-promoting importer implemented

## Purpose

External skill repositories are useful knowledge sources, but a familiar
publisher, a `SKILL.md` filename or a plugin manifest does not make their content
trusted, executable or compatible with an ecosystem deployment.

The implemented boundary is:

```text
already-local Git object at an exact commit
→ content-free import plan
→ human review and capability declaration
→ deterministic + adversarial proposal gate
→ exact-digest approval
→ separately owned promotion
```

The first arrow is implemented by `eco skills import-plan`. Every later arrow
remains a separate gate. Inspection cannot install or promote a skill.

## Microsoft Skills snapshot

Reviewed source:

- repository: [microsoft/skills](https://github.com/microsoft/skills);
- commit:
  [`4f1db7ec55caf11e3b143c91220bd79a632bc55b`](https://github.com/microsoft/skills/commit/4f1db7ec55caf11e3b143c91220bd79a632bc55b);
- commit object and working copy passed local Git integrity checks;
- no upstream script, hook, MCP server, package installer or eval harness was
  executed during review.

The repository is a large vendor content pack:

- 194 regular `SKILL.md` files;
- 189 observed unique non-empty names during the source audit;
- 1,253 declared eval scenarios in 137 scenario files;
- 60 tracked symlinks;
- Azure SDK packs for Python, .NET, Java, TypeScript and Rust;
- Azure deployment, Microsoft Foundry, Microsoft 365 and Deep Wiki packages;
- six project-specific agent definitions;
- an optional continual-learning hook.

It is valuable as a cookbook and UX/evaluation reference, but it is not a
drop-in trusted registry.

## Strong patterns worth adapting

1. Domain-specific SDK skills contain useful API patterns, troubleshooting and
   acceptance scenarios.
2. Azure deployment guidance uses a clear
   `plan → validate → approve → deploy → verify` interaction.
3. Deep Wiki requires real code-path tracing, file evidence, fact/inference
   separation, confidence and explicit unknowns.
4. Scenario and acceptance-criteria files are a useful base for skill
   evaluation.
5. Selective loading is treated as important; the upstream README itself warns
   that loading every skill causes context rot.
6. Plugin packaging shows useful discovery, grouping and dependency UX.

These are design inputs. Their prompt text cannot grant authority in the
ecosystem runtime.

## Material findings

### Broken Microsoft Foundry package

The snapshot advertises a Foundry v2 plugin with one orchestrator and ten
subskills, but ten symlinks point to absent Azure skill directories:

- governance;
- hosted agents;
- IQ knowledge bases;
- managed skills;
- memory;
- models;
- observability;
- projects/resources;
- toolboxes;
- workflows.

The upstream plugin validator explicitly skips its ordinary on-disk skill check
for `microsoft-foundry`, so the normal test path does not catch this regression.

### Evaluation is informative, not a merge gate

The smoke workflow captures the harness exit status and deliberately exits zero.
A later step emits a warning while its `exit 1` remains commented out. A green
workflow therefore does not establish that every skill scenario passed.

The real/nightly model evaluation is also optional and warning-oriented. This is
useful telemetry, but it is not equivalent to ecosystem promotion evidence.

### Runtime and supply-chain surfaces

The source includes MCP configurations for local and remote servers, including
`npx`, `uvx`, Docker and remote HTTP endpoints. Several use `@latest` or another
unpinned runtime identity. The Azure plugin also registers an opt-out telemetry
hook that invokes `npx -y @azure/mcp@latest`.

The hook can report client/event/session/skill/tool/reference-file metadata.
Although it does not intentionally send raw prompt or tool-result content, it is
still direct egress and cannot be an ecosystem default.

### Memory and agents

The optional continual-learning hook stores global SQLite state under the user
profile and local state under `.copilot-memory`. It derives lessons from recent
tool failures and injects them into later sessions. It is a useful product
prototype, but it does not provide the provenance, privacy class, TTL,
verification, conflict handling or policy separation required by ecosystem
memory.

The six custom agents are personas and handoffs for the upstream `CoreAI DIY`
project. They have broad tool labels and project-specific paths, but no
authenticated principals, task budgets, delegation narrowing, evidence edges or
independent authority gate. They are UX examples, not `AgentTeamManifest`
equivalents.

### Deep Wiki

Deep Wiki provides the strongest reusable research discipline in the source.
Its useful parts are actual call-path tracing, citations and confidence. Its
fixed five iterations and mandatory diagram/table per iteration are prompt-only
requirements, not measured budgets or independent gates. Some Deep Wiki skills
have acceptance criteria without runnable scenario files.

It should be reauthored under the ecosystem source-review and bounded-loop
contracts rather than copied verbatim.

## Implemented import-plan contract

The command is:

```bash
eco skills import-plan /local/git/repository \
  --source-uri https://github.com/microsoft/skills \
  --commit 4f1db7ec55caf11e3b143c91220bd79a632bc55b \
  --json
```

Properties:

- requires a full 40-character commit;
- accepts a credential-free HTTPS source identity;
- reads the Git tree and blobs from the exact commit, not mutable working-tree
  bytes;
- disables Git replacement-object semantics and repository hooks;
- rejects invalid/non-canonical paths, unexpected tree modes, malformed YAML,
  duplicate frontmatter keys, NUL/non-UTF-8/oversized skills and oversized
  trees;
- resolves symlinks lexically inside the pinned tree without following the
  filesystem;
- reports duplicate identities, broken/escaping symlinks, executables, hooks,
  MCP configs and bounded static signals;
- emits content digests but no skill body, description, secret, absolute path or
  raw Git error;
- writes no file and creates no model, network, credential or runtime authority.

Every candidate is emitted with `proposalEligible: false`. The plan explicitly
states that capabilities, owner, tests, evidence and source authenticity are not
established.

## Live result on the Microsoft snapshot

The final CLI run was repeated twice and produced byte-identical JSON:

- plan digest:
  `d09df5b1fe494a00a3de22676a60098b70276710bec150ba1204ffe479a9eb52`;
- tree digest:
  `e1c0078acad8d07373f69c8db13371e6596161ef938c70161837e1fcca2c22ca`;
- 1,982 tracked entries;
- 194 regular skill files;
- 186 review-required candidates;
- 8 blocked candidates;
- 60 tracked symlinks;
- 10 broken symlinks;
- 10 executable files;
- 8 hook files;
- 3 strict MCP config filenames;
- 5 skills with unpinned runtime references;
- promotion remained ineligible.

The eight blocked candidates are four duplicate-name entries and four malformed
or nested skill files without valid standalone frontmatter. This is a structural
finding, not a claim that the remaining 186 are safe or semantically correct.

## Verification

- 28 focused importer and existing skills-sync tests pass;
- pinned-blob tests prove mutable working-tree changes are ignored;
- negative tests cover duplicate YAML keys, duplicate names, escaping/broken
  symlinks, MCP/hooks/executables, invalid URI/commit, oversized content,
  selection closure and sanitized CLI failure;
- `eco validate`, `eco render --check`, `eco doctor` and `git diff --check`
  pass;
- the complete macOS suite remains platform-red for pre-existing Linux-only
  `openat2`/Landlock and `/var` alias behavior. The new tree ran 820 tests with
  25 failures, 67 errors and 26 skips; a pristine `HEAD` control ran 815 tests
  with 26 failures, 67 errors and 26 skips. All six added importer tests pass.

## Adoption decision

Adopt concepts:

- scenario-driven skill evaluation;
- selective catalog/discovery;
- Deep Wiki evidence discipline;
- Azure/Foundry capability taxonomy;
- approval UX and SDK knowledge packs.

Do not directly adopt:

- automatic telemetry;
- unpinned runtime downloads;
- direct MCP/network configuration;
- global learning databases;
- broad project personas as agents;
- prompt-only authorization;
- symlink packaging without integrity validation;
- non-blocking eval gates.

The next safe step is to select one useful source skill, rewrite it as a bounded
package-owned proposal, declare capabilities and evidence, prove the adversarial
gate catches a deliberately broken version, and only then request exact-digest
promotion.

## Sources

- [Pinned import architecture](../docs/architecture/upstream-skill-import.md)
- [Skills synchronization architecture](../docs/architecture/skills-harness-sync.md)
- [Importer implementation](../src/eco_skills/importer.py)
- [Import-plan schema](../src/eco_skills/schemas/upstream-import-plan.schema.json)
- [Importer tests](../tests/test_m6_upstream_skill_import.py)
- [Creation and promotion boundary](../docs/architecture/creation.md)
- [Private context memory](../docs/architecture/private-context-memory.md)
- [General agent teams](../docs/architecture/general-agent-teams.md)
