# M4 no-model wiki-health completion report

**Date:** 2026-07-16
**Scope:** fixed embedded Linux/WSL `wiki-health-check` profile and its L0–L2 promotion gate
**Result:** complete for the declared profile; L3–L5, scheduling, model use, network use, and writes remain denied

## Executive result

M4 now has one complete vertical slice:

```text
external signed snapshot
→ distinct no-model plan
→ exact policy decisions
→ authenticated external journal
→ descriptor-anchored broker reads
→ deterministic path/content-free report
→ five-attempt stability evaluation
→ zero-read recovery proof
→ maximum promotion L2
```

The implementation does not depend on DGX hardware or any AI provider. No local model, NIM, Claude, Copilot, Gemini, Codex, gateway, endpoint, adapter, or provider credential participates in this workflow.

## Delivered contracts

The model-routed `RunPlan` was not reused. M4 adds:

- `NoModelRunRequest` — fixed project plus `wiki-health-check` id;
- `NoModelRunPlan` — route-free A1 plan bound to current config and exact signed snapshot;
- `NoModelReadRequest` — transient exact path plus durable path-free slot binding;
- explicit `no-model.policy.*`, `no-model.workflow.*`, and `no-model.read.*` lifecycle events;
- `WikiHealthRunEvidence` — content/path-free attempt or recovery evidence;
- `WikiHealthPromotionReport` — frozen five-attempt/replay criteria and L0–L5 eligibility result.

The plan fixes:

- three code-owned entries: `wiki/index.md`, `wiki/architecture.md`, `wiki/roadmap.md`;
- D0 data, P1 trust, policy classification, A1 maximum action;
- three read requests;
- 30 seconds per attempt;
- exact signed input-byte sum;
- zero model, network, and workspace-write requests.

Durable plan scope contains only `scopeDigest`, three slot names, and entry digests. It contains no raw repository path, route, logical role, deployment, adapter, model, endpoint, tool catalog, credential, or write capability.

## Execution boundary

`eco run wiki-health-check --json` performs these steps:

1. validates canonical project configuration;
2. resolves only the declared external snapshot/key references;
3. verifies canonical HMAC evidence, issuer/key allowlist, project, repository-root identity, freshness, exact entry inventory, and classifications;
4. plans and consumes one exact no-model allow decision;
5. opens a private external authenticated journal;
6. for each fixed slot, issues and consumes a fresh expiring read decision using advancing policy time;
7. persists a `no-model.read.started` ambiguity fence immediately before the broker attempt;
8. reads through `RepositoryReadBroker` only;
9. verifies signed digest/length, UTF-8/regular-file/link safety, one H1 outside fenced code, distinct document digests, current evidence, and the durable deadline;
10. writes only sanitized event metadata and returns a stable report digest.

There is no fallback. Any missing/stale evidence, changed file, wrong root, forged plan, config drift, scope mismatch, deadline, unsafe state, broker failure, structural-health failure, or journal inconsistency becomes a typed failure.

## Journal and recovery evidence

The no-model journal is a deliberately separate SQLite application/schema profile. The governed repository is a forbidden state location. POSIX state must be externally provisioned, owner-only, and owned by the runtime user. Database/WAL/SHM symlinks, hardlinks, non-regular files, wrong permissions/ownership, wrong application/schema ids, and unexpected SQLite objects are rejected.

The operator supplies a separate `ECO_RUNTIME_JOURNAL_HMAC_KEY`. Domain-separated HMACs bind:

- run id plus exact plan digest;
- each canonical event;
- the current event-chain head.

The journal stores no raw path or document content. It holds a non-blocking exclusive database lock, so a second process fails before it can duplicate I/O. Recovery re-verifies current external signed evidence and replans. A previously `allowed` pre-start read is reauthorized and its new decision is consumed before broker I/O. A recovered `started` state is deliberately ambiguous and terminates with `ECO_NO_MODEL_READ_OUTCOME_AMBIGUOUS` without rereading. Completed slots restore sanitized digest/heading observations and are skipped. Terminal replay performs zero broker reads.

The first durable event anchors the 30-second deadline across recovery. Current policy time is derived from monotonic elapsed time rather than reusing the start timestamp. Evidence freshness and deadline checks therefore cover later read authorization, broker completion, content parsing, and terminal success.

This protects local integrity, not independent availability or rollback history. Deleting or restoring an older whole database cannot be detected without an independently retained anchor. The promotion evidence content digest is likewise not an issuer signature.

## Evaluation and promotion

`eco eval wiki-health-check --json` owns five fixed journal slots and one recovery replay. The schema-frozen gate requires:

| Criterion | Required |
|---|---:|
| Independent attempts | exactly 5 |
| Successful non-replayed historical attempts | 5 |
| Verified entries per attempt | 3 |
| Original broker reads per attempt | 3 |
| Recovery broker reads | 0 |
| Snapshot/report/count/byte drift | none |
| Unauthorized actions | 0 |
| Repository mutations | 0 |
| Model requests | 0 |
| Network requests | 0 |
| Write operations | 0 |
| Adapters/content emissions | 0 |

A pass makes L0, L1, and L2 eligible for this exact profile. The same report always marks L3, L4, and L5 ineligible with a fixed reason. CLI input cannot change attempt count, thresholds, scope, or eligible levels.

## Multi-agent review and corrections

Specialized contract, execution, evaluation, and adversarial reviewers were used. The first implementation was not accepted. Review reproduced and drove fixes for:

- an in-memory activation bypass that authorized a forged/unissued recovery plan;
- missing rebinding of plan snapshot/scope/config to current trusted evidence;
- adapter entry after no-model authorization but before workflow start;
- success after three arbitrary ids representing the same scope item;
- acceptance of artifact and budget events inside the no-model lifecycle;
- unauthenticated SQLite rows whose content and plain digest could be rewritten together;
- recovery from `allowed` without a fresh policy decision;
- stable run ids combined with changing plan timestamps, causing replay conflict;
- precreated database symlinks writing state into the repository;
- concurrent journal owners that could duplicate broker I/O;
- an overclaim that network denial was installed rather than network being unused;
- missing fixed initial event outcomes;
- report replay differences and absent promotion stability evidence;
- loss of completed digest/heading evidence during partial recovery;
- a fourth actual read after a crash between broker return and completion persistence;
- deadline bypass during final parsing/report completion;
- frozen policy time that allowed evidence to expire during a run.

Regression tests preserve each correction.

## Exit criteria

| Exit criterion | Evidence | Result |
|---|---|---|
| Separate no-model contract/lifecycle | distinct schemas, policy APIs, events and reducer | Pass |
| No model/route/adapter/endpoint | schema constants, absent fields, negative lifecycle tests | Pass |
| Exact signed three-entry scope | external evidence verification plus slot/entry rebinding | Pass |
| Single-use expiring decisions | plan/read issuance, consume, replay/expiry tests | Pass |
| Broker-only reads | fixed executor plus openat2 broker and call-count tests | Pass |
| No repository mutation | before/after full repository manifest test | Pass |
| Path/content-free output and state | sentinel scans of JSON and SQLite rows | Pass |
| Authenticated private state | HMAC/event/head, ownership/permission/schema/link tests | Pass |
| Restart/replay safety | pre-start reauthorization, partial/all-read recovery, ambiguous post-start terminal failure, zero duplicate I/O | Pass |
| Bounded execution | three attempt fences, exact bytes, durable 30-second deadline including parsing/success | Pass |
| Repeated-run promotion | five journals, stable result, zero-read recovery | Pass |
| L3–L5 denial | frozen report schema and evaluator tests | Pass |
| M1–M3 regression | complete unit/pytest/CLI/project gate | Pass |

## Verification

Local acceptance commands:

```text
python -m unittest discover -s tests -q     320 tests passed
python -m pytest                            passed
python -m compileall -q src tests           passed
eco validate                               passed
eco render --check                         passed
eco doctor                                 passed
git diff --check                           passed
```

The live command path is exercised against temporary externally signed fixtures and private external state. No signing API is called by production runtime code. Hosted CI result is recorded in the final evidence update after push.

## Exact non-claims

M4 does not claim:

- Windows/macOS broker conformance;
- full wiki link crawling, semantic staleness detection, or all-page duplicate detection;
- automatic wiki edits, proposals, approvals, or controlled apply;
- scheduler, autonomous retry, daemon, or kill-switch service;
- independent HMAC rollback detection or external journal availability;
- asymmetric/team identity, RBAC, revocation, or non-repudiation;
- a general workflow DSL or arbitrary repository inspection;
- L3, L4, L5, production autonomy, or readiness for `ml-autoresearch`.

Those require separately versioned scopes, identities, backends, fixtures, and promotion evidence.
