# Canonical skills and harness synchronization

**Status:** M6.2 bounded reference implementation; package-owned catalog only

## Outcome

`eco skills plan|sync|check|uninstall` projects a closed, digest-bound skill
catalog into several client layouts without importing or executing skill code.
The installed `eco_skills` package owns three dogfood workflows:

1. canonical ecosystem contract changes;
2. bounded loop authoring with explicit hard stops;
3. source-review claim and evidence discipline.

This is harness synchronization, not runtime authorization. A skill remains
guidance. Policy, credentials, tools, model egress, approvals and writes stay at
the M1–M6 enforcement boundaries.

## Canonical registry

Each closed registry entry binds stable id/version, package source URI and source
revision, SHA-256 of the exact UTF-8 bytes, license, owner, capabilities,
dependencies, tests, evidence, revocation and per-surface compatibility.

The source revision `package-release:m6.2-v1` identifies this built-in catalog
revision. It is deliberately not represented as an upstream Git commit. The
content digest is the exact byte identity. The separate
[upstream import-plan](upstream-skill-import.md) contract binds an immutable
external commit for review without adding it to this registry.

Registry loading uses JSON Schema plus cross-record checks for duplicate/case or
Unicode aliases, sorted identities, digest mismatch, unknown/cyclic dependencies,
invalid revocation and compatibility overclaim. Resource bytes are read as data
through package resources. No entry point, module, command, hook or discovered
repository file is executed.

## Projection contract

| Surface | Target | Claim |
|---|---|---|
| Codex | `.agents/skills/<id>/SKILL.md` | native skill-shaped projection |
| Claude | `.claude/skills/<id>/SKILL.md` | native skill-shaped projection |
| Gemini | `.gemini/skills/<id>/SKILL.md` | native skill-shaped projection |
| Portable | `.ai/skills/projected/<id>/SKILL.md` | generic bytes; automatic discovery not claimed |
| Copilot | `.github/instructions/eco-skills.instructions.md` | instruction-only aggregate |
| Cursor | `.cursor/rules/eco-skills.mdc` | instruction-only aggregate |

The Copilot and Cursor files say directly that native invocation, dependency
resolution and semantic parity are not claimed. File-layout similarity never
upgrades compatibility.

Every projection contains an `eco-skills:managed` marker. The deterministic
`.ai/skills/eco-skills.lock.json` binds registry revision, relative target,
surface, optional skill id and exact resulting content digest. The lock is
ownership evidence, not authority.

## Transaction and refusal rules

`plan` is zero-write. `sync` preflights all targets and refuses unmanaged files,
unowned byte matches, content drift, malformed/redirected lock entries, symbolic
links, hard links, non-regular files, traversal, non-NFC paths and case/Unicode
aliases. It writes deterministic bytes atomically and restores the complete
pre-operation snapshot on a catchable failure. `check` is read-only. `uninstall`
removes only unchanged files listed by a valid lock and restores the set if a
catchable removal fails. Unmanaged siblings are preserved.

## Verification and non-claims

Focused tests cover registry closure, traversal, case/Unicode aliases, symlink,
hardlink, unmanaged ownership, forged marker, drift, lock redirection, sync
rollback, uninstall rollback, deterministic lifecycle and CLI exit status.

This synchronization profile does not provide external download, signature or
transparency verification, live-client semantic conformance, skill execution,
automatic dependency installation, hostile concurrent parent-swap proof on every
OS, or native Windows/macOS filesystem security proof. Read-only inspection of an
already local pinned Git object is a separate non-promoting contract; the other
claims still require conformance and runtime authority boundaries.
