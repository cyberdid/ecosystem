# Autopilot cold start — dependency-method verification

**Date:** 2026-08-03
**Verifier:** Claude (Opus 5), via Claude Code
**Subject:** Nordrassil `main` at `3063b64`+ (S0–S8 of the autopilot goal)
**Method:** dependency method — positive proof plus a negative arm that must fail
without the concept under test

## Claim under test

> A specialist who knows none of Nordrassil's concepts connects a project and
> chats, and the system writes the concept layer for them — memory, wiki, skills,
> agents — derived from that specific project.

and its hard stop:

> Autonomy is not authority. The system may propose without being asked; it may
> never grant itself anything.

## Fixture

A synthetic UAV-navigation repository — the shape of the R&D case the goal
names — created fresh per arm:

```
uav-nav/
  README.md          # "# UAV navigation research" + a prose description
  pyproject.toml     # name = "uav-nav", description = "Inertial/GNSS fusion…"
  src/fusion.py
  tests/test_fusion.py
```

Stated intent, identical in every arm:

> rewrite the telemetry fusion stage so it survives dropped GNSS frames

Every service (brief, broker, synthesizer, autopilot loop, memory, documents,
provisioner) is pointed at temporary state. The three arms differ **only** in the
persisted capability set.

## Arms and results

| Arm | Capability set | Resolution | Loop | memory | documents | skills |
| --- | --- | --- | --- | --- | --- | --- |
| **Positive** | full stack **+ `autopilot.author` + `autopilot.run`** | `authored` / `NORDRASSIL_BROKER_AUTHORED` | `succeeded`, 5/5 stages | **1** | **1** | **1** |
| **Negative** | the same full stack, **no autopilot scope** | `unavailable` / `NORDRASSIL_BROKER_AUTHORING_NOT_PERMITTED` | `halted` at `resolve` | 0 | 0 | 0 |
| **Unrestricted** | full stack **+ `execution.superuser`**, no scope | `unavailable` / `NORDRASSIL_BROKER_AUTHORING_NOT_PERMITTED` | `halted` at `resolve` | 0 | 0 | 0 |

Artifacts produced in the positive arm:

- memory: one provenance-bound `fact` about the project's shape and subject
- document: `uav-nav — project overview`
- skill: `rewrite-telemetry-fusion-stage`, whose verification step names the
  project's own command, `python -m unittest discover -s tests`

## What each arm establishes

**The positive arm** shows the chain works from a folder to a concept layer with
no concept vocabulary required of the operator: the stack, entrypoints and test
command were derived from the project's own files; the subject line
("UAV navigation research") came from the project's README under an explicit
digest-bound consent, not from a guess; every proposal offered carried the
canonical validator that passed it; and every tool the plan intended to use was
put to the real capability gateway, each answering with enforcement tier
`core:team-access`.

**The negative arm** is what makes the positive arm mean anything. It is the same
run with the same capabilities and only the autopilot scopes removed. It halts at
`resolve` with the broker's own reason code and produces nothing. Had it still
produced the artifacts, autonomy would not have been their cause.

**The unrestricted arm** tests the hard stop directly. `execution.superuser`
turns off every product block — and still writes nothing unasked. Removing blocks
and deciding to act on one's own initiative are separate decisions, and the code
keeps them separate: `superuser_expansion` grants every capability except the
autopilot scopes.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_cold_start.py'
```

11 assertions across the three arms. The full suite is 322 tests, green.

## Honest limits

- The loop **prepares and asks; it does not dispatch.** The gate stage records
  what the core said about each intended tool; executing them remains the
  existing agent-run path. This verification therefore proves the concept layer
  is authored and gated, not that a task was carried out end to end.
- The authored skill is project-scoped and carries `registryPromotion:
  "not-earned"`. It is a well-formed proposal, not a package-registry entry.
- The fixture's own gate decisions are `ECO_TEAM_ACCESS_ALLOW_CANDIDATE` — an
  allow-candidate, never final signed runtime authority.
- Sub-task S2 (provisioning) is not exercised here: on the verifying host every
  installable runtime was already present, so the run was correctly empty. Its
  execution path is covered by `test_provision.py` against a fake Cookbook, and
  its planning path was confirmed live against the real Cookbook, producing
  `brew install ollama` then `ollama pull qwen3:32b` without executing either.
