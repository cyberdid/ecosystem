# Pinned upstream skill inspection

**Status:** bounded read-only import-plan contract

## Outcome

`eco skills import-plan` inspects skill-shaped content from one exact local Git
commit and emits a deterministic, content-free `UpstreamSkillImportPlan`. It is
an offline source-review boundary, not an installer, marketplace client,
registry mutation, compatibility claim or execution runtime.

An upstream repository is untrusted even when its owner, host or license is
familiar. The command therefore reads blobs from the requested commit through
Git object plumbing. It does not read mutable working-tree skill bytes, fetch a
remote, load hooks, execute scripts, start MCP servers, install dependencies or
consume credentials.

## Contract

The caller supplies:

- a local Git repository containing the already-fetched object;
- an HTTPS source URI without credentials, query or fragment;
- the full 40-character commit id;
- an optional closed selection of skill ids.

The plan binds the exact commit, a digest of the complete Git tree, skill content
digests, normalized repository-relative paths, frontmatter validity, duplicate
identities, tracked symlinks and bounded static risk signals. Local absolute paths
and skill bodies are absent from the result.

`source.authenticity` is deliberately `not-established`: existence of a commit
in a local object database does not authenticate its author, upstream ownership,
signature, freshness or license. Those require separately trusted evidence.

## Fail-closed inspection

The inspector rejects malformed commit ids and source URIs, missing Git objects,
non-UTF-8 or non-canonical paths, oversized trees and malformed Git output.
Regular `SKILL.md` blobs are bounded, UTF-8 decoded without NUL bytes, and parsed
with duplicate-key rejection. Invalid, duplicate or oversized skill candidates
are blocked.

Tracked symlinks are never followed through the filesystem. Their target is
normalized lexically inside the pinned tree. Absolute, escaping or missing
targets are `blocked` or `broken`. Submodules, executable files, hook paths, MCP
configuration and unpinned runtime references are reported as repository
signals; no signal is executed.

Every external candidate remains `proposalEligible: false`, including a
structurally clean candidate. An operator must author or review a bounded
proposal, declare capabilities, bind tests/evidence/owner, pass the adversarial
GSC gate and approve the exact digest before any separate promotion.

## Determinism and safety

The plan digest covers the complete report except its own digest field. Repeating
inspection for the same commit, source URI and selection produces identical
bytes. The command performs zero repository writes and creates no rollback or
uninstall work because there is no mutation to reverse.

The schema is
`src/eco_skills/schemas/upstream-import-plan.schema.json`. Tests cover pinned
blob isolation from working-tree changes, zero-write determinism, selection,
duplicate identity, broken aliases, execution signals and CLI failure
sanitization.

## Explicit non-claims

This contract does not:

- fetch, authenticate or update an upstream;
- verify a Git signature, transparency log, author or license;
- infer safe capabilities from prose;
- establish semantic compatibility with a client;
- copy a candidate into the package registry or a harness;
- execute an eval, tool, hook, MCP server, agent or model;
- make upstream memory, telemetry or approval language authoritative.
